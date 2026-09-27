"""Call the Jac evidence ladder. Classification decisions are not made here."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LADDER = ROOT / "ladder" / "classify.jac"


def jac_binary() -> str:
    override = os.environ.get("JACKNIFE_JAC", "")
    if override:
        return override
    found = shutil.which("jac")
    if found:
        return found
    candidate = Path.home() / ".local" / "bin" / "jac"
    if candidate.is_file():
        return str(candidate)
    raise RuntimeError("jac is not installed; pip install -r requirements.txt")


def classify_many(evidences: list[dict]) -> list[str]:
    if not evidences:
        return []
    proc = subprocess.run(
        [jac_binary(), "run", str(LADDER)],
        input=json.dumps(evidences),
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"jac ladder failed: {detail[:500]}")
    labels = json.loads(proc.stdout)
    if not isinstance(labels, list) or len(labels) != len(evidences):
        raise RuntimeError("jac ladder returned an unexpected payload")
    if not all(isinstance(label, str) for label in labels):
        raise RuntimeError("jac ladder returned a non-string label")
    return labels


def evidence_for_ladder(
    finding: dict,
    *,
    artifact_verified: bool,
    workflow_corroborated: bool,
    attestation_verified: bool,
) -> dict:
    evidence = finding["evidence"]
    return {
        "simulated": evidence["simulated"],
        "rejected": evidence["rejected"],
        "reproduced": evidence["reproduced"],
        "minimized": evidence["minimized"],
        "artifact_verified": artifact_verified,
        "workflow_corroborated": workflow_corroborated,
        "attestation_verified": attestation_verified,
        "sanitizer": finding["sanitizer"],
        "crash_type": finding["crash_type"],
        "input_hex": finding["input_hex"],
        "stack_trace": finding["stack_trace"],
        "report_excerpt": evidence["report_excerpt"],
    }
