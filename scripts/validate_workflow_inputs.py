#!/usr/bin/env python3
"""Validate workflow_dispatch inputs from the environment and emit sanitized values.

Raw inputs are never interpolated into a shell by the workflow. This process
reads them from the environment and writes only allowlisted values to
GITHUB_ENV and GITHUB_OUTPUT.
"""

from __future__ import annotations

import os
import re
import sys

RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGITS = re.compile(r"^[0-9]+$")
REPO = "MPH04/JacKnife"


def fail(message: str) -> None:
    sys.stderr.write(message + "\n")
    raise SystemExit(2)


def sanitized() -> dict[str, str]:
    run_id = os.environ.get("JACKNIFE_INPUT_RUN_ID", "")
    duration_raw = os.environ.get("JACKNIFE_INPUT_DURATION", "")
    seed_raw = os.environ.get("JACKNIFE_INPUT_SEED", "")
    for label, value in (
        ("run_id", run_id),
        ("duration_seconds", duration_raw),
        ("seed", seed_raw),
    ):
        if "\n" in value or "\r" in value or "\x00" in value:
            fail(f"{label} contains a control character")
    if not RUN_ID.fullmatch(run_id):
        fail("run_id is invalid")
    if duration_raw == "":
        duration_raw = "90"
    if seed_raw == "":
        seed_raw = "1"
    if not DIGITS.fullmatch(duration_raw) or not DIGITS.fullmatch(seed_raw):
        fail("duration_seconds and seed must be unsigned integers")
    duration = int(duration_raw)
    seed = int(seed_raw)
    if not 1 <= duration <= 300:
        fail("duration_seconds must be from 1 to 300")
    if seed > 4294967295:
        fail("seed is out of range")

    repository = os.environ.get("JACKNIFE_GITHUB_REPOSITORY", "")
    if repository and repository != REPO:
        fail("repository is not MPH04/JacKnife")
    sha = os.environ.get("JACKNIFE_GITHUB_SHA", "")
    if sha and not SHA.fullmatch(sha):
        fail("commit sha is invalid")
    github_run = os.environ.get("JACKNIFE_GITHUB_RUN_ID", "")
    if github_run and (not DIGITS.fullmatch(github_run) or github_run == "0"):
        fail("github run id is invalid")
    server = os.environ.get("JACKNIFE_GITHUB_SERVER_URL", "")
    if server and server != "https://github.com":
        fail("github server url is invalid")
    workflow_url = ""
    if github_run and server == "https://github.com":
        workflow_url = f"https://github.com/{REPO}/actions/runs/{int(github_run)}"
    return {
        "JACKNIFE_RUN_ID": run_id,
        "JACKNIFE_DURATION": str(duration),
        "JACKNIFE_SEED": str(seed),
        "JACKNIFE_COMMIT_SHA": sha,
        "JACKNIFE_GITHUB_RUN_ID": str(int(github_run)) if github_run else "",
        "JACKNIFE_WORKFLOW_URL": workflow_url,
        "JACKNIFE_REPOSITORY": REPO,
        "artifact_name": "jacknife-" + run_id,
    }


def _append(path: str, lines: list[str]) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        for line in lines:
            if "\n" in line or "\r" in line:
                fail("refusing to write a multiline workflow value")
            handle.write(line + "\n")


def main() -> int:
    values = sanitized()
    env_path = os.environ.get("GITHUB_ENV", "")
    out_path = os.environ.get("GITHUB_OUTPUT", "")
    if env_path:
        _append(
            env_path,
            [
                f"JACKNIFE_RUN_ID={values['JACKNIFE_RUN_ID']}",
                f"JACKNIFE_DURATION={values['JACKNIFE_DURATION']}",
                f"JACKNIFE_SEED={values['JACKNIFE_SEED']}",
                f"JACKNIFE_COMMIT_SHA={values['JACKNIFE_COMMIT_SHA']}",
                f"JACKNIFE_GITHUB_RUN_ID={values['JACKNIFE_GITHUB_RUN_ID']}",
                f"JACKNIFE_WORKFLOW_URL={values['JACKNIFE_WORKFLOW_URL']}",
                f"JACKNIFE_REPOSITORY={values['JACKNIFE_REPOSITORY']}",
                "JACKNIFE_SOURCE=github-actions",
            ],
        )
    if out_path:
        _append(out_path, [f"artifact_name={values['artifact_name']}"])
    if not env_path and not out_path:
        sys.stdout.write(
            "ok run_id={run} duration={duration} seed={seed} artifact={artifact}\n".format(
                run=values["JACKNIFE_RUN_ID"],
                duration=values["JACKNIFE_DURATION"],
                seed=values["JACKNIFE_SEED"],
                artifact=values["artifact_name"],
            )
        )
    else:
        sys.stdout.write("inputs accepted\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
