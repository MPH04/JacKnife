# jkpacket target

JacKnife owns this parser. The layout is a small stateful packet, in the same
spirit as a public "riftpacket" exercise, but the bytes, opcodes, and bugs
below were written for this repository.

## Frame layout

```
offset  size  field
0       4     magic "JKPK"
then repeated frames, at most 16:
0       1     opcode
1       1     flags
2       1     reserved, ignored
3       2     payload length, little-endian
5       N     payload, N = payload length
```

The length is checked against the bytes that remain in the input. It is not
checked against the buffer the opcode writes into. That is deliberate.

| Opcode | Name | Behavior |
| --- | --- | --- |
| 0x01 | BIND | `malloc(16)`, then `memcpy` of the claimed length |
| 0x03 | LABEL | `memcpy` into an 8-byte stack array |
| 0x04 | DROP | `free` the session buffer and keep the pointer |
| 0x05 | READ | load `buf[0]` when a buffer has been allocated or freed |
| 0x06 | SCALE | add two little-endian int32 values from the payload |

## Seeded bugs

### JK-HEAP-001 — heap-buffer-overflow

`bug_heap_bind` in `target/jkpacket.c` allocates 16 bytes and copies `claimed`
bytes. A BIND frame whose payload is present and longer than 16 bytes writes
past the allocation. AddressSanitizer reports `heap-buffer-overflow`. The
source read stays inside the fuzzer input because the parser refuses a frame
whose payload is not fully present.

Corpus: `target/corpus/seed_heap.bin` (64-byte payload).

### JK-STACK-001 — stack-buffer-overflow

`bug_stack_label` copies `claimed` bytes into `char label[8]`. A LABEL frame
longer than 8 bytes is a stack overflow. AddressSanitizer reports
`stack-buffer-overflow`.

Corpus: `target/corpus/seed_stack.bin`.

### JK-UAF-001 — heap-use-after-free

DROP frees the BIND buffer and leaves the pointer in place (`live` becomes
dangling). READ then loads the first byte. AddressSanitizer reports
`heap-use-after-free`. The valid BIND payload is 4 bytes, so this seed does
not also trip the heap overflow.

Corpus: `target/corpus/seed_uaf.bin`.

### JK-UB-001 — signed-integer-overflow

`bug_scale_add` computes `left + right` as `int32_t`. The seed uses
`INT_MAX` and `1`. UndefinedBehaviorSanitizer prints
`runtime error: signed integer overflow`. Clang 18's SUMMARY line says
`undefined-behavior`, which JacKnife does **not** treat as a class by itself.
The class `signed-integer-overflow` is taken from the runtime error sentence.

Corpus: `target/corpus/seed_ubsan.bin`.

## What is not a sanitizer bug

A frame whose claimed length runs past the end of the input is rejected by
the parser and does not crash. More than 16 frames are ignored. LeakSanitizer
is disabled (`detect_leaks=0`) because these bugs are not leak bugs; an
exit-time leak report would be a different claim.

## Build

```bash
bash scripts/install_toolchain.sh
bash scripts/build_fuzzer.sh
bash scripts/reproduce_crash.sh target/corpus/seed_heap.bin
```

The compiler flags are:

```text
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
```

`-fno-omit-frame-pointer` is there so the stacks name the C functions. It does
not change the sanitizer class.
