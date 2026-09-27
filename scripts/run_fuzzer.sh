#!/usr/bin/env bash
# Run a time-bounded libFuzzer campaign. Crashes do not stop the campaign.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source "${ROOT}/scripts/sanitizer_env.sh"

if [[ ! -x "${ROOT}/build/fuzz_jkpacket" ]]; then
    echo "fuzzer binary missing; run scripts/build_fuzzer.sh" >&2
    exit 1
fi

DURATION="${JACKNIFE_DURATION:-90}"
SEED="${JACKNIFE_SEED:-1}"
OUT_DIR="${JACKNIFE_CRASH_DIR:-${ROOT}/runs/crashes}"

if ! [[ "${DURATION}" =~ ^[0-9]+$ ]]; then
    echo "JACKNIFE_DURATION must be an integer" >&2
    exit 1
fi
if (( DURATION < 1 || DURATION > 300 )); then
    echo "JACKNIFE_DURATION must be between 1 and 300" >&2
    exit 1
fi
if ! [[ "${SEED}" =~ ^[0-9]+$ ]]; then
    echo "JACKNIFE_SEED must be an integer" >&2
    exit 1
fi

mkdir -p "${OUT_DIR}"
# libFuzzer writes new coverage inputs into its first corpus directory.
# Copy the committed seeds so target/corpus stays stable.
WORK_CORPUS="${ROOT}/runs/corpus"
rm -rf "${WORK_CORPUS}"
mkdir -p "${WORK_CORPUS}"
cp "${ROOT}/target/corpus"/seed_*.bin "${WORK_CORPUS}/"
# Ignore crashes so one seeded bug does not end the campaign.
# -fork=1 keeps going after a child dies. Crash files land in OUT_DIR.
set +e
"${ROOT}/build/fuzz_jkpacket" \
    "${WORK_CORPUS}" \
    -fork=1 \
    -ignore_crashes=1 \
    -ignore_ooms=1 \
    -ignore_timeouts=1 \
    -max_total_time="${DURATION}" \
    -timeout=10 \
    -rss_limit_mb=2048 \
    -max_len=4096 \
    -seed="${SEED}" \
    -artifact_prefix="${OUT_DIR}/" \
    -print_final_stats=1
STATUS=$?
set -e

# Clang 18's libFuzzer can exit 134 after a timed run even when -ignore_crashes=1
# saved crash files. A campaign that left crashes behind is complete.
if [[ "${STATUS}" -eq 0 ]]; then
    echo "campaign finished; crash dir ${OUT_DIR}"
    exit 0
fi
if compgen -G "${OUT_DIR}/crash-*" > /dev/null; then
    echo "campaign saved crashes (fuzzer status ${STATUS}); crash dir ${OUT_DIR}"
    exit 0
fi
echo "fuzzer exited ${STATUS} and wrote no crash files" >&2
exit "${STATUS}"
