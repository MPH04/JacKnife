#!/usr/bin/env bash
# Shared sanitizer environment for local and CI runs.
# LeakSanitizer is left off: the seeded bugs are spatial, temporal, and UB,
# and an exit-time leak report would be a different class than the ones we claim.
if [[ -z "${ASAN_SYMBOLIZER_PATH:-}" ]]; then
    if [[ -x /usr/bin/llvm-symbolizer-18 ]]; then
        export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-18
    elif [[ -x /usr/bin/llvm-symbolizer ]]; then
        export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
    fi
fi
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:color=never:abort_on_error=1:halt_on_error=1:symbolize=1:print_summary=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:color=never:halt_on_error=1:symbolize=1:print_summary=1}"
export LSAN_OPTIONS="${LSAN_OPTIONS:-color=never}"
