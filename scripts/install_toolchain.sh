#!/usr/bin/env bash
# Install clang, the matching sanitizer runtime, and llvm-symbolizer.
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
    APT=(apt-get)
else
    APT=(sudo apt-get)
fi

"${APT[@]}" update
if ! command -v clang >/dev/null 2>&1; then
    "${APT[@]}" install -y clang llvm g++
fi

VER="$(clang -dumpversion | cut -d. -f1)"
"${APT[@]}" install -y "clang-${VER}" "llvm-${VER}" "libclang-rt-${VER}-dev" g++

if [[ -x "/usr/bin/llvm-symbolizer-${VER}" ]]; then
    echo "symbolizer=/usr/bin/llvm-symbolizer-${VER}"
elif [[ -x /usr/bin/llvm-symbolizer ]]; then
    echo "symbolizer=/usr/bin/llvm-symbolizer"
else
    echo "llvm-symbolizer not found after install" >&2
    exit 1
fi
