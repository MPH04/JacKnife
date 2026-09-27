#!/usr/bin/env python3
"""Fail closed wrapper around `gh attestation verify`.

A missing gh binary, a missing bundle, or a non-zero gh status is not
verification. This script never accepts a token as an argument.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from scripts.textsafe import redact

REPO = "MPH04/JacKnife"


def verify(artifact: Path, repo: str = REPO) -> int:
    if repo != REPO:
        sys.stderr.write("refusing to verify an attestation for a different repo\n")
        return 1
    if artifact.is_symlink() or not artifact.is_file():
        sys.stderr.write("artifact is not a regular file\n")
        return 1
    gh = shutil.which("gh")
    if not gh:
        sys.stderr.write("gh is not installed; attestation not verified\n")
        return 1
    env = os.environ.copy()
    token = env.get("JACKNIFE_GITHUB_TOKEN", "")
    if token and not env.get("GH_TOKEN") and not env.get("GITHUB_TOKEN"):
        env["GH_TOKEN"] = token
    proc = subprocess.run(
        [gh, "attestation", "verify", str(artifact), "--repo", repo],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    stdout = redact(proc.stdout or "", token)
    stderr = redact(proc.stderr or "", token)
    if stdout:
        sys.stdout.write(stdout)
        if not stdout.endswith("\n"):
            sys.stdout.write("\n")
    if proc.returncode != 0:
        sys.stderr.write(stderr or "attestation verification failed\n")
        return 1
    if "verified" not in (stdout + stderr).lower():
        # gh's success wording has changed before. Require an explicit
        # verification phrase so a quiet non-zero-less bug cannot pass.
        sys.stderr.write("gh exited 0 without a verification phrase; not verified\n")
        return 1
    return 0


def main() -> int:
    if any(arg == "--token" or arg.startswith("--token=") for arg in sys.argv[1:]):
        sys.stderr.write("refusing a token on the command line\n")
        return 2
    argp = argparse.ArgumentParser(description="Verify a GitHub artifact attestation")
    argp.add_argument("--artifact", type=Path, required=True)
    argp.add_argument("--repo", default=REPO)
    args = argp.parse_args()
    return verify(args.artifact, args.repo)


if __name__ == "__main__":
    raise SystemExit(main())
