#!/usr/bin/env python3
"""Write the JacKnife corpus. Seeds are data for our own parser, stored as hex."""

from __future__ import annotations

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "target" / "corpus"


def frame(opcode: int, flags: int, payload: bytes) -> bytes:
    if not 0 <= opcode <= 255 or not 0 <= flags <= 255:
        raise ValueError("opcode/flags out of range")
    if len(payload) > 65535:
        raise ValueError("payload too large")
    return bytes((opcode, flags, 0)) + struct.pack("<H", len(payload)) + payload


def packet(*frames: bytes) -> bytes:
    return b"JKPK" + b"".join(frames)


def main() -> None:
    CORPUS.mkdir(parents=True, exist_ok=True)
    seeds = {
        "seed_valid.bin": packet(frame(0x01, 0x00, b"ok")),
        "seed_heap.bin": packet(frame(0x01, 0x00, b"H" * 64)),
        "seed_stack.bin": packet(frame(0x03, 0x00, b"S" * 32)),
        "seed_uaf.bin": packet(
            frame(0x01, 0x00, b"NAME"),
            frame(0x04, 0x00, b""),
            frame(0x05, 0x00, b""),
        ),
        "seed_ubsan.bin": packet(
            frame(0x06, 0x00, struct.pack("<ii", 2**31 - 1, 1))
        ),
    }
    for name, blob in seeds.items():
        (CORPUS / name).write_bytes(blob)
        (CORPUS / (name + ".hex")).write_text(blob.hex() + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
