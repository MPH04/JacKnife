#!/usr/bin/env bash
# Build the libFuzzer harness with ASan and UBSan.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p build target/corpus
python3 scripts/write_seeds.py

clang -g -O1 \
    -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=undefined \
    -fno-omit-frame-pointer \
    -I target \
    target/jkpacket.c \
    target/fuzz_jkpacket.c \
    -o build/fuzz_jkpacket

echo "built ${ROOT}/build/fuzz_jkpacket"
