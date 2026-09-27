#!/usr/bin/env python3
"""Reject hostile or inconsistent JacKnife artifacts.

The zip is never extracted with archive paths. Only the two allowlisted
members are read, and only after name, size, and compression checks.
"""

from __future__ import annotations

import argparse
import io
import os
import stat
import sys
import zipfile
from pathlib import Path

from scripts.ladder_bridge import classify_many, evidence_for_ladder
from scripts.schema import (
    REPO,
    SchemaError,
    loads,
    sha256_bytes,
    validate_manifest,
    validate_state,
)
from scripts.textsafe import has_hostile

MAX_ZIP_BYTES = 5 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_FILES = 8
MAX_RATIO = 50
ALLOWED = {"state.json", "manifest.json"}
TARGET_FILES = (
    "target/jkpacket.c",
    "target/jkpacket.h",
    "target/fuzz_jkpacket.c",
)


class ArtifactRejected(Exception):
    pass


def _reject(message: str) -> None:
    raise ArtifactRejected(message)


def _check_name(name: str) -> None:
    if name in ("", ".", ".."):
        _reject("empty archive name")
    if name != name.strip() or "\\" in name or "\x00" in name:
        _reject("archive name is not a plain file")
    if name.startswith("/") or name.startswith("~"):
        _reject("absolute archive name")
    parts = name.split("/")
    if len(parts) != 1 or parts[0] in ("", ".", ".."):
        _reject("archive name is not a single path segment")
    if parts[0] not in ALLOWED:
        _reject("archive member is not allowlisted")


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_IFMT(mode) == stat.S_IFLNK


def read_zip(path: Path) -> dict[str, bytes]:
    if path.is_symlink():
        _reject("artifact path is a symlink")
    size = path.stat().st_size
    if size <= 0 or size > MAX_ZIP_BYTES:
        _reject("zip size is outside the allowed range")
    raw = path.read_bytes()
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        _reject(f"zip is unreadable: {exc}")
    infos = archive.infolist()
    if len(infos) == 0 or len(infos) > MAX_FILES:
        _reject("zip member count is outside the allowed range")
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        _reject("duplicate archive member")
    total = 0
    files: dict[str, bytes] = {}
    for info in infos:
        _check_name(info.filename)
        if _is_symlink(info):
            _reject("symlink archive member")
        if info.is_dir():
            _reject("directory archive member")
        if info.file_size < 0 or info.file_size > MAX_FILE_BYTES:
            _reject("uncompressed member is too large")
        if info.compress_size <= 0 and info.file_size > 0:
            _reject("suspicious compression size")
        if info.compress_size > 0 and (info.file_size / info.compress_size) > MAX_RATIO:
            _reject("compression ratio is too high")
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            _reject("uncompressed total is too large")
        files[info.filename] = archive.read(info)
        if len(files[info.filename]) != info.file_size:
            _reject("member size mismatch")
    missing = ALLOWED - set(files)
    if missing:
        _reject("required artifact files are missing")
    return files


def read_dir(path: Path) -> dict[str, bytes]:
    if path.is_symlink() or not path.is_dir():
        _reject("artifact directory is not a real directory")
    files: dict[str, bytes] = {}
    for child in path.iterdir():
        if child.is_symlink():
            _reject("artifact directory contains a symlink")
        if not child.is_file():
            _reject("artifact directory contains a non-file")
        if child.name not in ALLOWED:
            _reject("unexpected file in artifact directory")
        data = child.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            _reject("artifact file is too large")
        files[child.name] = data
    if set(files) != ALLOWED:
        _reject("artifact directory is missing required files")
    return files


def _check_targets(manifest: dict, root: Path) -> None:
    for name in TARGET_FILES:
        digest = sha256_bytes((root / name).read_bytes())
        if manifest["target_hashes"][name] != digest:
            _reject(f"target hash mismatch for {name}")


def _labels_for(state: dict, *, workflow_corroborated: bool, attestation_verified: bool) -> list[str]:
    payloads = [
        evidence_for_ladder(
            finding,
            artifact_verified=True,
            workflow_corroborated=workflow_corroborated,
            attestation_verified=attestation_verified,
        )
        for finding in state["findings"]
    ]
    return classify_many(payloads)


def validate_files(
    files: dict[str, bytes],
    *,
    check_targets: bool,
    repo_root: Path,
    workflow_corroborated: bool = False,
    attestation_verified: bool = False,
) -> dict:
    for blob in files.values():
        if b"\x00" in blob:
            _reject("artifact JSON contains a NUL")
    try:
        state_text = files["state.json"].decode("utf-8")
        manifest_text = files["manifest.json"].decode("utf-8")
    except UnicodeError as exc:
        _reject(f"artifact is not utf-8: {exc}")
    try:
        state = loads(state_text)
        manifest = loads(manifest_text)
        # Producer artifacts must not carry promotion flags. A corroborated
        # re-check is a separate document (verified-state.json), not this zip.
        validate_state(state, allow_promotion_flags=False)
        validate_manifest(manifest, state, files["state.json"])
    except SchemaError as exc:
        _reject(str(exc))
    if manifest["repo"] != REPO or manifest["workflow"] != "fuzz.yml":
        _reject("wrong repo or workflow")
    if check_targets:
        _check_targets(manifest, repo_root)
    for finding in state["findings"]:
        if has_hostile(finding["stack_trace"]) or has_hostile(finding["evidence"]["report_excerpt"]):
            _reject("unescaped hostile text in finding")
    labels = _labels_for(
        state,
        workflow_corroborated=workflow_corroborated,
        attestation_verified=attestation_verified,
    )
    for finding, label in zip(state["findings"], labels):
        if finding["classification"] != label:
            _reject(
                f"classification {finding['classification']!r} does not match ladder {label!r}"
            )
        if label in ("Confirmed", "Attested") and not workflow_corroborated and not attestation_verified:
            _reject("promotion label without corroboration")
    return {"state": state, "manifest": manifest, "classifications": labels}


def main() -> int:
    argp = argparse.ArgumentParser(description="Validate a JacKnife artifact")
    group = argp.add_mutually_exclusive_group(required=True)
    group.add_argument("--zip", type=Path)
    group.add_argument("--dir", type=Path)
    argp.add_argument("--check-targets", action="store_true")
    argp.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = argp.parse_args()
    try:
        files = read_zip(args.zip) if args.zip else read_dir(args.dir)
        result = validate_files(files, check_targets=args.check_targets, repo_root=args.repo_root)
    except ArtifactRejected as exc:
        sys.stderr.write(f"rejected: {exc}\n")
        return 1
    sys.stdout.write(
        f"accepted findings={len(result['state']['findings'])} "
        f"run_id={result['state']['run_id']}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
