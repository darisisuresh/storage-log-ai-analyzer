from __future__ import annotations

import re

REDACTIONS = (
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_REDACTED]"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "[EMAIL_REDACTED]"),
    (re.compile(r"(?i)\b(serial|wwn|wwpn|iqn|naa|array[ _-]?id)\s*[:=]\s*\S+"), r"\1=[IDENTIFIER_REDACTED]"),
    (re.compile(r"\b[a-f0-9]{24,}\b", re.I), "[LONG_ID_REDACTED]"),
)


def redact(text: str) -> str:
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text
