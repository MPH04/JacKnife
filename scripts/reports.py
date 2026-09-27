"""Parse AddressSanitizer and UndefinedBehaviorSanitizer stderr."""

from __future__ import annotations

import re

from scripts.textsafe import escape_untrusted

_ASAN_ERROR = re.compile(r"ERROR: AddressSanitizer: ([a-z0-9-]+)")
_RUNTIME = re.compile(r"runtime error: ([^\n]+)")
_UBSAN_SUMMARY = re.compile(r"SUMMARY: UndefinedBehaviorSanitizer:")
_SITE = re.compile(r"\bin ([A-Za-z_][A-Za-z0-9_]*)\b[^\n]*jkpacket\.c:\d+")

# Wording clang 18 prints. The generic SUMMARY token "undefined-behavior"
# is not a class: the specific class is the runtime error sentence.
_UBSAN_PHRASES = (
    ("signed integer overflow", "signed-integer-overflow"),
    ("shift exponent", "shift-exponent"),
    ("left shift of negative", "invalid-shift-base"),
    ("division by zero", "integer-divide-by-zero"),
    ("misaligned address", "alignment"),
    ("null pointer", "null-pointer"),
    ("out of bounds", "out-of-bounds"),
    ("pointer overflow", "pointer-overflow"),
    ("execution reached an unreachable program point", "unreachable"),
)


def parse_report(raw: str) -> dict | None:
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    asan = _ASAN_ERROR.search(text)
    if asan:
        crash_type = asan.group(1)
        sanitizer = "address"
    elif _UBSAN_SUMMARY.search(text):
        runtime = _RUNTIME.search(text)
        if not runtime:
            return None
        sentence = runtime.group(1)
        crash_type = ""
        for phrase, name in _UBSAN_PHRASES:
            if phrase in sentence:
                crash_type = name
                break
        if not crash_type:
            return None
        sanitizer = "undefined"
    else:
        return None

    excerpt = _excerpt(text)
    site_match = _SITE.search(text)
    site = site_match.group(1) if site_match else ""
    return {
        "sanitizer": sanitizer,
        "crash_type": crash_type,
        "site": site,
        "report_excerpt": escape_untrusted(excerpt),
        "stack_trace": escape_untrusted(excerpt),
    }


def _excerpt(text: str) -> str:
    lines = text.split("\n")
    start = None
    for index, line in enumerate(lines):
        if "ERROR: AddressSanitizer:" in line or "runtime error:" in line:
            start = index
            break
    if start is None:
        return ""
    kept: list[str] = []
    for line in lines[start : start + 80]:
        if line.startswith("Shadow bytes") or line.startswith("  0x"):
            break
        kept.append(line)
        if line.startswith("SUMMARY:"):
            break
    return "\n".join(kept)
