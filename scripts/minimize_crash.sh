#!/usr/bin/env bash
# Minimize one crashing input without changing its sanitizer class.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ $# -ne 2 ]]; then
    echo "usage: scripts/minimize_crash.sh INPUT OUTPUT" >&2
    exit 2
fi
if [[ ! -f "$1" ]]; then
    echo "input not found" >&2
    exit 2
fi
if [[ ! -x "${ROOT}/build/fuzz_jkpacket" ]]; then
    echo "fuzzer binary missing; run scripts/build_fuzzer.sh" >&2
    exit 1
fi

export PYTHONPATH="${ROOT}${PYTHONPATH:+:${PYTHONPATH}}"
python3 "${ROOT}/scripts/shrink_crash.py" "$1" "$2"
