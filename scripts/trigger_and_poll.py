#!/usr/bin/env python3
"""Dispatch the JacKnife fuzz workflow, poll it, and download the artifact.

The token is read only from JACKNIFE_GITHUB_TOKEN. It is never accepted as an
argument and is redacted if a transport error echoes it back.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from scripts.schema import dumps
from scripts.textsafe import redact
from scripts.validate_artifact import ArtifactRejected, read_zip, validate_files
from scripts.ladder_bridge import classify_many, evidence_for_ladder

REPO = "MPH04/JacKnife"
TOKEN_ENV = "JACKNIFE_GITHUB_TOKEN"
API = "https://api.github.com"
ALLOWED_HOSTS = {
    "api.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "codeload.github.com",
}
MAX_POLLS = 80
POLL_SECONDS = 15


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def host_allowed(hostname: str) -> bool:
    host = (hostname or "").lower().rstrip(".")
    if host in ALLOWED_HOSTS:
        return True
    if host.endswith(".blob.core.windows.net") and host != ".blob.core.windows.net":
        return True
    if host.endswith(".actions.githubusercontent.com") and not host.startswith("."):
        return True
    return False


def _stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def run_corroborates(run: dict, *, repo: str, run_id: str, commit_sha: str) -> tuple[bool, str]:
    if run.get("event") != "workflow_dispatch":
        return False, "event"
    if run.get("path") != ".github/workflows/fuzz.yml":
        return False, "path"
    if run.get("name") != f"fuzz-{run_id}":
        return False, "name"
    if run.get("head_sha") != commit_sha:
        return False, "sha"
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return False, "conclusion"
    expected = f"https://github.com/{repo}/actions/runs/{run.get('id')}"
    if run.get("html_url") != expected:
        return False, "url"
    repo_name = ((run.get("repository") or {}).get("full_name")) if isinstance(run.get("repository"), dict) else None
    if repo_name not in (None, repo):
        return False, "repository"
    return True, "ok"


def default_transport(method: str, url: str, body: bytes | None, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    current = url
    payload = body
    for _ in range(5):
        parsed = urlparse(current)
        if parsed.scheme != "https" or not host_allowed(parsed.hostname or ""):
            raise ApiError(0, "refusing a redirect or URL outside the GitHub host allowlist")
        request = urllib.request.Request(current, data=payload if parsed.hostname == "api.github.com" else None, method=method if parsed.hostname == "api.github.com" else "GET")
        for key, value in headers.items():
            if key.lower() == "authorization" and parsed.hostname != "api.github.com":
                continue
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response:
                return response.status, dict(response.headers.items()), response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                current = exc.headers.get("Location", "")
                payload = None
                method = "GET"
                continue
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise ApiError(exc.code, f"github api status {exc.code}: {detail}") from exc
    raise ApiError(0, "too many redirects")


def promote(state: dict, corroboration: dict) -> dict:
    payloads = [
        evidence_for_ladder(
            finding,
            artifact_verified=True,
            workflow_corroborated=True,
            attestation_verified=corroboration.get("attestation") == "verified",
        )
        for finding in state["findings"]
    ]
    labels = classify_many(payloads) if payloads else []
    promoted = json.loads(json.dumps(state))
    for finding, label in zip(promoted["findings"], labels):
        finding["classification"] = label
        finding["evidence"]["artifact_verified"] = True
        finding["evidence"]["workflow_corroborated"] = True
        finding["evidence"]["attestation_verified"] = corroboration.get("attestation") == "verified"
    promoted["corroboration"] = corroboration
    return promoted


def trigger_and_poll(
    *,
    run_id: str,
    duration: int,
    seed: int,
    out_zip: Path,
    out_dir: Path,
    token: str,
    transport=default_transport,
    sleep=time.sleep,
    now=None,
) -> dict:
    from scripts.validate_workflow_inputs import RUN_ID

    if not RUN_ID.fullmatch(run_id):
        raise ApiError(0, "run_id is invalid")
    if not 1 <= duration <= 300 or not 0 <= seed <= 4294967295:
        raise ApiError(0, "duration or seed is out of range")
    started = now or datetime.now(timezone.utc)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "JacKnife",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    def call(method: str, url: str, payload: dict | None = None) -> tuple[int, bytes]:
        body = None if payload is None else json.dumps(payload).encode()
        try:
            status, _headers, data = transport(method, url, body, headers)
        except ApiError as exc:
            raise ApiError(exc.status, redact(str(exc), token)) from exc
        return status, data

    status, _ = call(
        "POST",
        f"{API}/repos/{REPO}/actions/workflows/fuzz.yml/dispatches",
        {
            "ref": "main",
            "inputs": {
                "run_id": run_id,
                "duration_seconds": str(duration),
                "seed": str(seed),
            },
        },
    )
    if status != 204:
        raise ApiError(status, f"dispatch returned {status}")

    match = None
    for _attempt in range(MAX_POLLS):
        status, data = call(
            "GET",
            f"{API}/repos/{REPO}/actions/workflows/fuzz.yml/runs?event=workflow_dispatch&per_page=20",
        )
        if status != 200:
            raise ApiError(status, f"listing runs returned {status}")
        payload = json.loads(data.decode())
        found = []
        for run in payload.get("workflow_runs", []):
            created = run.get("created_at")
            # Allow a little clock skew between this machine and GitHub.
            if not created or _stamp(created) < started - timedelta(seconds=30):
                continue
            if run.get("name") == f"fuzz-{run_id}" and run.get("path") == ".github/workflows/fuzz.yml":
                found.append(run)
        if len(found) > 1:
            raise ApiError(0, "ambiguous workflow runs for this run_id")
        if len(found) == 1 and found[0].get("status") == "completed":
            match = found[0]
            break
        sleep(POLL_SECONDS)
    if match is None:
        raise ApiError(0, "timed out waiting for the workflow run")
    if match.get("conclusion") != "success":
        raise ApiError(0, f"workflow conclusion {match.get('conclusion')}")

    status, data = call("GET", f"{API}/repos/{REPO}/actions/runs/{match['id']}/artifacts")
    if status != 200:
        raise ApiError(status, f"listing artifacts returned {status}")
    artifacts = json.loads(data.decode()).get("artifacts", [])
    expected_name = "jacknife-" + run_id
    chosen = [item for item in artifacts if item.get("name") == expected_name and not item.get("expired")]
    if len(chosen) != 1:
        raise ApiError(0, "expected exactly one matching artifact")
    artifact = chosen[0]
    status, blob = call("GET", f"{API}/repos/{REPO}/actions/artifacts/{artifact['id']}/zip")
    if status != 200 or not blob:
        raise ApiError(status, "artifact download failed")
    if out_zip.is_symlink():
        raise ApiError(0, "refusing to write through a symlink")
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    out_zip.write_bytes(blob)
    try:
        files = read_zip(out_zip)
        validated = validate_files(files, check_targets=False, repo_root=Path("."))
    except ArtifactRejected as exc:
        raise ApiError(0, f"downloaded artifact rejected: {exc}") from exc
    state = validated["state"]
    manifest = validated["manifest"]
    ok, reason = run_corroborates(
        match,
        repo=REPO,
        run_id=run_id,
        commit_sha=state["commit_sha"] or "",
    )
    if not ok:
        raise ApiError(0, f"workflow run failed corroboration: {reason}")
    if manifest["github_run_id"] != match["id"] or state["run_id"] != run_id:
        raise ApiError(0, "artifact identity does not match the observed run")
    corroboration = {
        "method": "github-api",
        "github_run_id": match["id"],
        "run_name": match.get("name"),
        "head_sha": match.get("head_sha"),
        "artifact_name": expected_name,
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "attestation": "not-checked",
    }
    verified = promote(state, corroboration)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "verified-state.json").write_text(dumps(verified), encoding="utf-8")
    return {"run": match, "verified": verified, "zip": str(out_zip)}


def main() -> int:
    if any(arg == "--token" or arg.startswith("--token=") for arg in sys.argv[1:]):
        sys.stderr.write("refusing a token on the command line\n")
        return 2
    argp = argparse.ArgumentParser(description="Trigger, poll, and download a JacKnife fuzz run")
    argp.add_argument("--repo", default=REPO)
    argp.add_argument("--run-id", required=True)
    argp.add_argument("--duration", type=int, default=90)
    argp.add_argument("--seed", type=int, default=1)
    argp.add_argument("--out-zip", type=Path, required=True)
    argp.add_argument("--out-dir", type=Path)
    args = argp.parse_args()
    if args.repo != REPO:
        sys.stderr.write("this client only talks to MPH04/JacKnife\n")
        return 2
    token = os.environ.get(TOKEN_ENV, "")
    if not token:
        sys.stderr.write(f"set {TOKEN_ENV}\n")
        return 2
    out_dir = args.out_dir or args.out_zip.parent
    try:
        result = trigger_and_poll(
            run_id=args.run_id,
            duration=args.duration,
            seed=args.seed,
            out_zip=args.out_zip,
            out_dir=out_dir,
            token=token,
        )
    except ApiError as exc:
        sys.stderr.write(redact(str(exc), token) + "\n")
        return 1
    verified = result["verified"]
    labels = sorted({item["classification"] for item in verified["findings"]}) or ["none"]
    sys.stdout.write(
        f"run {result['run']['id']} artifact {args.out_zip} labels {', '.join(labels)}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
