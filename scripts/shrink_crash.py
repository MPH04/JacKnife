#!/usr/bin/env python3
"""Class-preserving crash minimizer.

libFuzzer's minimizer only preserves "still crashes". On this target that can
change a heap overflow into a different sanitizer class. This minimizer keeps
an input only when the sanitizer, crash type, and site stay the same.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts.reports import parse_report

ROOT = Path(__file__).resolve().parents[1]
FUZZER = ROOT / "build" / "fuzz_jkpacket"
MAX_INPUT_BYTES = 8192


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault(
        "ASAN_OPTIONS",
        "detect_leaks=0:color=never:abort_on_error=1:halt_on_error=1:symbolize=1:print_summary=1",
    )
    env.setdefault(
        "UBSAN_OPTIONS",
        "print_stacktrace=1:color=never:halt_on_error=1:symbolize=1:print_summary=1",
    )
    if not env.get("ASAN_SYMBOLIZER_PATH"):
        for candidate in ("/usr/bin/llvm-symbolizer-18", "/usr/bin/llvm-symbolizer"):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                env["ASAN_SYMBOLIZER_PATH"] = candidate
                break
    return env


def replay(blob: bytes) -> tuple[int, str]:
    if not blob or len(blob) > MAX_INPUT_BYTES or not FUZZER.is_file():
        return 0, ""
    with tempfile.NamedTemporaryFile(prefix="jacknife-min-", delete=False) as handle:
        handle.write(blob)
        path = Path(handle.name)
    try:
        proc = subprocess.run(
            [str(FUZZER), str(path), "-runs=1"],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
            env=_env(),
            cwd=ROOT,
        )
    finally:
        path.unlink(missing_ok=True)
    return proc.returncode, proc.stderr + "\n" + proc.stdout


def signature(blob: bytes) -> tuple[str, str, str] | None:
    status, report = replay(blob)
    if status == 0:
        return None
    parsed = parse_report(report)
    if not parsed:
        return None
    return (parsed["sanitizer"], parsed["crash_type"], parsed["site"])


def _shorten_length_prefixes(current: bytes, original: tuple[str, str, str]) -> bytes:
    """Shrink little-endian length fields without changing the sanitizer class.

    A field is treated as a length only when its value is at most the bytes
    that follow it, and at most 128. The search keeps the smallest value that
    still reproduces the same class, then keeps whatever bytes followed the
    original payload so later frames stay intact.
    """
    changed = True
    while changed:
        changed = False
        for index in range(0, len(current) - 1):
            claimed = current[index] | (current[index + 1] << 8)
            remain = len(current) - (index + 2)
            if not (0 < claimed <= min(remain, 128)):
                continue
            for new_len in range(0, claimed):
                prefix = bytes((new_len & 0xFF, (new_len >> 8) & 0xFF))
                tail = current[index + 2 + claimed :]
                trial = current[:index] + prefix + current[index + 2 : index + 2 + new_len] + tail
                if signature(trial) == original:
                    current = trial
                    changed = True
                    break
            if changed:
                break
    return current


def shrink(data: bytes) -> bytes | None:
    original = signature(data)
    if original is None:
        return None
    current = _shorten_length_prefixes(data, original)
    # ddmin. Subsets that change the sanitizer class are rejected.
    parts = 2
    while len(current) >= 2:
        chunk = max(1, len(current) // parts)
        reduced = False
        start = 0
        while start < len(current):
            trial = current[:start] + current[start + chunk :]
            if len(trial) >= 4 and signature(trial) == original:
                current = trial
                parts = max(2, parts - 1)
                reduced = True
                break
            start += chunk
        if reduced:
            continue
        if parts >= len(current):
            break
        parts = min(len(current), parts * 2)
    return current


def main() -> int:
    argp = argparse.ArgumentParser(description="Minimize a crash without changing its sanitizer class")
    argp.add_argument("input", type=Path)
    argp.add_argument("output", type=Path)
    args = argp.parse_args()
    data = args.input.read_bytes()
    result = shrink(data)
    if result is None:
        sys.stderr.write("input did not reproduce a recognized sanitizer class\n")
        return 1
    args.output.write_bytes(result)
    sys.stdout.write(f"minimized {len(data)} -> {len(result)} bytes\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
