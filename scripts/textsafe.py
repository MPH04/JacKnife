"""Escape untrusted crash text before it is stored or displayed."""

from __future__ import annotations

import re

# Bidirectional and line-separator characters that can spoof a later viewer.
_HOSTILE = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\u200e",
    "\u200f",
    "\u061c",
    "\u2028",
    "\u2029",
}
_ANSI = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def escape_untrusted(text: str, limit: int = 12000) -> str:
    """Return a single-line ASCII-safe rendering of untrusted text.

    Newlines, ANSI, HTML metacharacters, and bidi controls become visible
    ``\\uXXXX`` sequences. The result is what Jac and the validator see.
    """
    cleaned = _ANSI.sub("", text)
    out: list[str] = []
    size = 0
    for ch in cleaned:
        code = ord(ch)
        if ch in _HOSTILE or ch in "<>&" or code < 32 or code == 127:
            piece = "\\u%04x" % code
        else:
            piece = ch
        if size + len(piece) > limit:
            break
        out.append(piece)
        size += len(piece)
    return "".join(out)


def has_hostile(text: str) -> bool:
    if "\x1b" in text or any(mark in text for mark in _HOSTILE):
        return True
    if any(ch in text for ch in "<>&"):
        return True
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


def redact(text: str, secret: str) -> str:
    if not secret or not text:
        return text
    return text.replace(secret, "[redacted]")
