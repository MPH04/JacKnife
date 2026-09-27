#!/usr/bin/env bash
# Replay one input under the sanitizer build. Exit status is the fuzzer's.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source "${ROOT}/scripts/sanitizer_env.sh"

if [[ $# -ne 1 ]]; then
    echo "usage: scripts/reproduce_crash.sh INPUT" >&2
    exit 2
fi

INPUT="$1"
if [[ ! -f "${INPUT}" ]]; then
    echo "input not found" >&2
    exit 2
fi
if [[ ! -x "${ROOT}/build/fuzz_jkpacket" ]]; then
    echo "fuzzer binary missing; run scripts/build_fuzzer.sh" >&2
    exit 1
fi

# -runs=1 executes this input and stops. A sanitizer abort is a non-zero status.
set +e
"${ROOT}/build/fuzz_jkpacket" "${INPUT}" -runs=1
STATUS=$?
set -e
exit "${STATUS}"
