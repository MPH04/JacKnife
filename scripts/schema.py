"""Closed schema checks for state.json and manifest.json."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SCHEMA_VERSION = "1"
REPO = "MPH04/JacKnife"
WORKFLOW = "fuzz.yml"
GENERATOR = "jacknife"

CLASSIFICATIONS = {
    "Sample",
    "Real crash captured",
    "Reproduced",
    "Minimized",
    "Sanitizer-classified (ASan)",
    "Sanitizer-classified (UBSan)",
    "Attested",
    "Confirmed",
    "Rejected",
    "Unknown",
}

_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_INPUT = re.compile(r"^[0-9a-f]{2,16384}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_WORKFLOW_URL = re.compile(r"^https://github.com/MPH04/JacKnife/actions/runs/[1-9][0-9]*$")

STATE_KEYS = {
    "schema_version",
    "generator",
    "run_id",
    "run_date",
    "source",
    "workflow_url",
    "commit_sha",
    "duration_seconds",
    "seed",
    "crash_files_seen",
    "findings",
}
FINDING_KEYS = {
    "finding_id",
    "classification",
    "sanitizer",
    "crash_type",
    "input_hex",
    "stack_trace",
    "reproducible",
    "minimized",
    "site",
    "evidence",
}
EVIDENCE_KEYS = {
    "simulated",
    "rejected",
    "reproduced",
    "minimized",
    "artifact_verified",
    "workflow_corroborated",
    "attestation_verified",
    "report_excerpt",
}
MANIFEST_KEYS = {
    "schema_version",
    "repo",
    "workflow",
    "run_id",
    "github_run_id",
    "commit_sha",
    "source",
    "run_date",
    "tool_versions",
    "file_hashes",
    "duration_seconds",
    "seed",
    "target_hashes",
    "crash_files_seen",
}
TOOL_KEYS = {"clang", "python", "jaclang", "libfuzzer"}
TARGET_FILES = ("target/jkpacket.c", "target/jkpacket.h", "target/fuzz_jkpacket.c")


class SchemaError(ValueError):
    pass


def loads(raw: str) -> Any:
    if raw.startswith("\ufeff") or raw.startswith("\xef\xbb\xbf"):
        raise SchemaError("JSON BOM is not allowed")
    try:
        return json.loads(raw, object_pairs_hook=_pairs)
    except SchemaError:
        raise
    except json.JSONDecodeError as exc:
        raise SchemaError(f"invalid JSON: {exc.msg}") from exc


def dumps(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _pairs(pairs: list[tuple[Any, Any]]) -> dict:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str):
            raise SchemaError("JSON keys must be strings")
        if key in obj:
            raise SchemaError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _exact_keys(obj: dict, allowed: set[str], label: str) -> None:
    extra = set(obj) - allowed
    missing = allowed - set(obj)
    if extra or missing:
        raise SchemaError(f"{label} keys mismatch extra={sorted(extra)} missing={sorted(missing)}")


def _bool(obj: dict, key: str) -> None:
    if type(obj[key]) is not bool:
        raise SchemaError(f"{key} must be a boolean")


def _u32(value: Any, label: str, upper: int) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise SchemaError(f"{label} must be an integer")
    if value < 0 or value > upper:
        raise SchemaError(f"{label} out of range")
    return value


def validate_state(state: Any, *, allow_promotion_flags: bool) -> dict:
    if not isinstance(state, dict):
        raise SchemaError("state.json must be an object")
    _exact_keys(state, STATE_KEYS, "state")
    if state["schema_version"] != SCHEMA_VERSION or state["generator"] != GENERATOR:
        raise SchemaError("unexpected schema_version or generator")
    if not isinstance(state["run_id"], str) or not _RUN_ID.fullmatch(state["run_id"]):
        raise SchemaError("run_id is invalid")
    if not isinstance(state["run_date"], str) or not _DATE.fullmatch(state["run_date"]):
        raise SchemaError("run_date must be UTC RFC3339")
    if state["source"] not in ("local", "github-actions"):
        raise SchemaError("source is invalid")
    url = state["workflow_url"]
    if url is None:
        if state["source"] == "github-actions":
            raise SchemaError("github-actions results need a workflow_url")
    elif not isinstance(url, str) or not _WORKFLOW_URL.fullmatch(url):
        raise SchemaError("workflow_url is invalid")
    sha = state["commit_sha"]
    if sha is not None and (not isinstance(sha, str) or not _HEX40.fullmatch(sha)):
        raise SchemaError("commit_sha is invalid")
    _u32(state["duration_seconds"], "duration_seconds", 300)
    if state["duration_seconds"] < 1:
        raise SchemaError("duration_seconds out of range")
    _u32(state["seed"], "seed", 4294967295)
    _u32(state["crash_files_seen"], "crash_files_seen", 100000)
    findings = state["findings"]
    if not isinstance(findings, list) or len(findings) > 64:
        raise SchemaError("findings must be a list of at most 64")
    seen: set[str] = set()
    for finding in findings:
        _validate_finding(finding, allow_promotion_flags=allow_promotion_flags)
        if finding["finding_id"] in seen:
            raise SchemaError("duplicate finding_id")
        seen.add(finding["finding_id"])
    return state


def _validate_finding(finding: Any, *, allow_promotion_flags: bool) -> None:
    if not isinstance(finding, dict):
        raise SchemaError("finding must be an object")
    _exact_keys(finding, FINDING_KEYS, "finding")
    if not isinstance(finding["finding_id"], str) or not _HEX16.fullmatch(finding["finding_id"]):
        raise SchemaError("finding_id is invalid")
    if finding["classification"] not in CLASSIFICATIONS:
        raise SchemaError("classification is not an allowed label")
    if finding["sanitizer"] not in ("address", "undefined", ""):
        raise SchemaError("sanitizer is invalid")
    if not isinstance(finding["crash_type"], str) or len(finding["crash_type"]) > 64:
        raise SchemaError("crash_type is invalid")
    if finding["crash_type"] and not re.fullmatch(r"[a-z0-9-]{1,64}", finding["crash_type"]):
        raise SchemaError("crash_type is invalid")
    if not isinstance(finding["input_hex"], str) or not _HEX_INPUT.fullmatch(finding["input_hex"]):
        raise SchemaError("input_hex must be lowercase hex")
    if not isinstance(finding["stack_trace"], str) or len(finding["stack_trace"]) > 20000:
        raise SchemaError("stack_trace is invalid")
    _bool(finding, "reproducible")
    _bool(finding, "minimized")
    if not isinstance(finding["site"], str) or len(finding["site"]) > 128:
        raise SchemaError("site is invalid")
    if finding["site"] and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", finding["site"]):
        raise SchemaError("site is invalid")
    evidence = finding["evidence"]
    if not isinstance(evidence, dict):
        raise SchemaError("evidence must be an object")
    _exact_keys(evidence, EVIDENCE_KEYS, "evidence")
    for key in (
        "simulated",
        "rejected",
        "reproduced",
        "minimized",
        "artifact_verified",
        "workflow_corroborated",
        "attestation_verified",
    ):
        _bool(evidence, key)
    if not isinstance(evidence["report_excerpt"], str) or len(evidence["report_excerpt"]) > 20000:
        raise SchemaError("report_excerpt is invalid")
    if finding["reproducible"] != evidence["reproduced"]:
        raise SchemaError("reproducible does not match evidence")
    if finding["minimized"] != evidence["minimized"]:
        raise SchemaError("minimized does not match evidence")
    if not allow_promotion_flags:
        if evidence["artifact_verified"] or evidence["workflow_corroborated"] or evidence["attestation_verified"]:
            raise SchemaError("artifact claims a promotion flag the producer cannot set")
        if finding["classification"] in ("Confirmed", "Attested"):
            raise SchemaError("artifact claims Confirmed or Attested")


def validate_manifest(manifest: Any, state: dict, state_bytes: bytes) -> dict:
    if not isinstance(manifest, dict):
        raise SchemaError("manifest.json must be an object")
    _exact_keys(manifest, MANIFEST_KEYS, "manifest")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise SchemaError("manifest schema_version mismatch")
    if manifest["repo"] != REPO or manifest["workflow"] != WORKFLOW:
        raise SchemaError("manifest repo or workflow mismatch")
    if manifest["run_id"] != state["run_id"] or manifest["source"] != state["source"]:
        raise SchemaError("manifest does not match state identity")
    if manifest["run_date"] != state["run_date"] or manifest["commit_sha"] != state["commit_sha"]:
        raise SchemaError("manifest does not match state revision")
    if manifest["duration_seconds"] != state["duration_seconds"] or manifest["seed"] != state["seed"]:
        raise SchemaError("manifest does not match state run parameters")
    if manifest["crash_files_seen"] != state["crash_files_seen"]:
        raise SchemaError("manifest crash count mismatch")
    github_run_id = manifest["github_run_id"]
    if github_run_id is None:
        if state["source"] == "github-actions":
            raise SchemaError("github_run_id missing")
    else:
        _u32(github_run_id, "github_run_id", 10**15)
        if github_run_id < 1:
            raise SchemaError("github_run_id out of range")
        expected = f"https://github.com/MPH04/JacKnife/actions/runs/{github_run_id}"
        if state["workflow_url"] != expected:
            raise SchemaError("workflow_url does not match github_run_id")
    tools = manifest["tool_versions"]
    if not isinstance(tools, dict):
        raise SchemaError("tool_versions must be an object")
    _exact_keys(tools, TOOL_KEYS, "tool_versions")
    for key, value in tools.items():
        if not isinstance(value, str) or not value or len(value) > 200 or "\n" in value:
            raise SchemaError(f"tool version {key} is invalid")
    hashes = manifest["file_hashes"]
    if not isinstance(hashes, dict):
        raise SchemaError("file_hashes must be an object")
    _exact_keys(hashes, {"state.json"}, "file_hashes")
    recorded = hashes["state.json"]
    if not isinstance(recorded, str) or not _SHA256.fullmatch(recorded):
        raise SchemaError("state.json hash is invalid")
    if recorded != sha256_bytes(state_bytes):
        raise SchemaError("state.json hash mismatch")
    targets = manifest["target_hashes"]
    if not isinstance(targets, dict):
        raise SchemaError("target_hashes must be an object")
    _exact_keys(targets, set(TARGET_FILES), "target_hashes")
    for name, digest in targets.items():
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise SchemaError(f"bad target hash for {name}")
    return manifest
