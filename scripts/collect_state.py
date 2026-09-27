#!/usr/bin/env python3
"""Reproduce, minimize, and classify crashes into state.json and manifest.json."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from scripts.ladder_bridge import classify_many, evidence_for_ladder, jac_binary
from scripts.reports import parse_report
from scripts.shrink_crash import replay, shrink
from scripts.schema import SCHEMA_VERSION, dumps, sha256_bytes, validate_manifest, validate_state
from scripts.textsafe import escape_untrusted

ROOT = Path(__file__).resolve().parents[1]
FUZZER = ROOT / "build" / "fuzz_jkpacket"
REPRO = ROOT / "scripts" / "reproduce_crash.sh"
TARGET_FILES = (
    "target/jkpacket.c",
    "target/jkpacket.h",
    "target/fuzz_jkpacket.c",
)
MAX_CRASH_FILES = 48
MAX_INPUT_BYTES = 8192


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
        cwd=ROOT,
    )


def reproduce(path: Path) -> tuple[int, str]:
    proc = _run(["bash", str(REPRO), str(path)], timeout=30)
    return proc.returncode, proc.stderr + "\n" + proc.stdout


def git_sha() -> str | None:
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    if dirty.strip() or len(sha) != 40:
        return None
    return sha


def tool_versions() -> dict[str, str]:
    clang = subprocess.check_output(["clang", "--version"], text=True).splitlines()[0].strip()
    jac = "0.9.11"
    try:
        jac_out = subprocess.check_output(
            [jac_binary(), "--version"],
            text=True,
            stderr=subprocess.STDOUT,
        )
        for line in jac_out.splitlines():
            if "Version:" in line:
                jac = line.split("Version:", 1)[1].strip()
                break
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return {
        "clang": clang[:200],
        "python": sys.version.split()[0],
        "jaclang": jac[:200],
        "libfuzzer": "libclang_rt.fuzzer (clang)",
    }


def target_hashes() -> dict[str, str]:
    hashes = {}
    for name in TARGET_FILES:
        hashes[name] = sha256_bytes((ROOT / name).read_bytes())
    return hashes


def finding_id(sanitizer: str, crash_type: str, site: str) -> str:
    raw = f"{sanitizer}|{crash_type}|{site}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _inputs_from_dir(crash_dir: Path) -> list[Path]:
    files = [path for path in crash_dir.iterdir() if path.is_file() and path.name.startswith("crash-")]
    files.sort(key=lambda path: (path.stat().st_size, path.name))
    return files[:MAX_CRASH_FILES]


def _finding_from(parsed: dict, blob: bytes, minimized: bool) -> dict:
    site = parsed["site"]
    stack = escape_untrusted(parsed["stack_trace"])
    excerpt = escape_untrusted(parsed["report_excerpt"])
    evidence = {
        "simulated": False,
        "rejected": False,
        "reproduced": True,
        "minimized": minimized,
        "artifact_verified": False,
        "workflow_corroborated": False,
        "attestation_verified": False,
        "report_excerpt": excerpt,
    }
    return {
        "finding_id": finding_id(parsed["sanitizer"], parsed["crash_type"], site),
        "classification": "",
        "sanitizer": parsed["sanitizer"],
        "crash_type": parsed["crash_type"],
        "input_hex": blob.hex(),
        "stack_trace": stack,
        "reproducible": True,
        "minimized": minimized,
        "site": site,
        "evidence": evidence,
    }


def scout(path: Path) -> dict | None:
    if path.stat().st_size > MAX_INPUT_BYTES:
        return None
    status, report = reproduce(path)
    if status == 0:
        return None
    parsed = parse_report(report)
    if not parsed:
        return None
    return _finding_from(parsed, path.read_bytes(), False)


def apply_shrink(finding: dict) -> dict:
    original = bytes.fromhex(finding["input_hex"])
    shrunk = shrink(original)
    if shrunk is None or len(shrunk) > len(original):
        return finding
    status_min, report_min = replay(shrunk)
    parsed_min = parse_report(report_min) if status_min != 0 else None
    if not parsed_min:
        return finding
    if (
        parsed_min["crash_type"] != finding["crash_type"]
        or parsed_min["sanitizer"] != finding["sanitizer"]
        or parsed_min["site"] != finding["site"]
    ):
        return finding
    return _finding_from(parsed_min, shrunk, True)


def classify_findings(findings: list[dict]) -> None:
    payloads = [
        evidence_for_ladder(
            finding,
            artifact_verified=False,
            workflow_corroborated=False,
            attestation_verified=False,
        )
        for finding in findings
    ]
    labels = classify_many(payloads)
    for finding, label in zip(findings, labels):
        finding["classification"] = label


def collect(paths: list[Path]) -> list[dict]:
    best: dict[str, dict] = {}
    for path in paths:
        try:
            finding = scout(path)
        except subprocess.TimeoutExpired:
            continue
        if not finding:
            continue
        current = best.get(finding["finding_id"])
        if current is None or len(finding["input_hex"]) < len(current["input_hex"]):
            best[finding["finding_id"]] = finding
    findings = [apply_shrink(finding) for finding in best.values()]
    findings.sort(key=lambda item: item["finding_id"])
    if findings:
        classify_findings(findings)
    return findings


def assemble(findings: list[dict], seen: int, args: argparse.Namespace) -> tuple[dict, dict]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commit = args.commit_sha if args.commit_sha is not None else git_sha()
    if commit == "":
        commit = None
    workflow_url = args.workflow_url or None
    if workflow_url == "":
        workflow_url = None
    github_run_id = args.github_run_id
    state = {
        "schema_version": SCHEMA_VERSION,
        "generator": "jacknife",
        "run_id": args.run_id,
        "run_date": now,
        "source": args.source,
        "workflow_url": workflow_url,
        "commit_sha": commit,
        "duration_seconds": args.duration,
        "seed": args.seed,
        "crash_files_seen": seen,
        "findings": findings,
    }
    state_bytes = dumps(state).encode()
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "repo": "MPH04/JacKnife",
        "workflow": "fuzz.yml",
        "run_id": args.run_id,
        "github_run_id": github_run_id,
        "commit_sha": commit,
        "source": args.source,
        "run_date": now,
        "tool_versions": tool_versions(),
        "file_hashes": {"state.json": sha256_bytes(state_bytes)},
        "duration_seconds": args.duration,
        "seed": args.seed,
        "target_hashes": target_hashes(),
        "crash_files_seen": seen,
    }
    validate_state(state, allow_promotion_flags=False)
    validate_manifest(manifest, state, state_bytes)
    return state, manifest


def parser() -> argparse.ArgumentParser:
    argp = argparse.ArgumentParser(description="Build state.json from sanitizer crashes")
    argp.add_argument("--crash-dir", type=Path)
    argp.add_argument("--inputs", nargs="*", type=Path, default=[])
    argp.add_argument("--out-dir", type=Path, required=True)
    argp.add_argument("--run-id", default=os.environ.get("JACKNIFE_RUN_ID", "local"))
    argp.add_argument("--duration", type=int, default=int(os.environ.get("JACKNIFE_DURATION", "90")))
    argp.add_argument("--seed", type=int, default=int(os.environ.get("JACKNIFE_SEED", "1")))
    argp.add_argument("--source", default=os.environ.get("JACKNIFE_SOURCE", "local"))
    argp.add_argument("--commit-sha", default=os.environ.get("JACKNIFE_COMMIT_SHA"))
    argp.add_argument("--workflow-url", default=os.environ.get("JACKNIFE_WORKFLOW_URL"))
    argp.add_argument("--github-run-id", default=os.environ.get("JACKNIFE_GITHUB_RUN_ID") or None)
    return argp


def main() -> int:
    args = parser().parse_args()
    if args.github_run_id is not None:
        args.github_run_id = int(args.github_run_id)
    paths: list[Path] = list(args.inputs)
    seen = 0
    if args.crash_dir:
        if not args.crash_dir.is_dir():
            sys.stderr.write("crash dir not found\n")
            return 1
        discovered = _inputs_from_dir(args.crash_dir)
        seen = len(list(args.crash_dir.glob("crash-*")))
        paths.extend(discovered)
    if not paths:
        sys.stderr.write("no crash inputs\n")
        return 1
    findings = collect(paths)
    if seen == 0:
        seen = len(paths)
    state, manifest = assemble(findings, seen, args)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "state.json").write_text(dumps(state), encoding="utf-8")
    (args.out_dir / "manifest.json").write_text(dumps(manifest), encoding="utf-8")
    sys.stdout.write(f"wrote {len(findings)} findings to {args.out_dir}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
