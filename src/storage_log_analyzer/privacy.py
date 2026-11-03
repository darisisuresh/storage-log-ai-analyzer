from __future__ import annotations

import hashlib
import ipaddress
import re

# This helper is for local sharing; AI requests use an allowlisted aggregate schema
# and never include raw evidence, paths, identifiers, or arbitrary log fields.
SENSITIVE_KEYS = r'password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|serial|wwn|wwpn|iqn|naa|array(?:[_ -]?(?:id|name))?|host(?:name)?|device(?:[_ -]?id)?|user(?:name)?|customer(?:[_ -]?id)?|tenant(?:[_ -]?id)?|share|path'
FIELD = re.compile(rf'(?i)(["\']?\b(?:{SENSITIVE_KEYS})["\']?\s*[:=]\s*)("[^"\n]*"|\'[^\'\n]*\'|[^\s,;}}]+)')
BEARER = re.compile(r'(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+')
EMAIL = re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.I)
IP = re.compile(r'(?<![\w:])(?:[a-fA-F0-9]*:){2,}[a-fA-F0-9:.]*(?:%[\w.-]+)?|\b(?:\d{1,3}\.){3}\d{1,3}\b')
PATH = re.compile(r'(?:[A-Za-z]:[\\/]|\\\\)[^\s"\'<>]+|(?<![\w:])/(?:[^\s/"\'<>]+/)*[^\s"\'<>]*')
HOST = re.compile(r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]*\b')
KEY = re.compile(r'\b(?:sk-[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|[a-f0-9]{24,})\b', re.I)


def _pseudonym(kind, value):
    # Stable within the text, without keeping an unbounded mapping of input values.
    return f'[{kind}_{hashlib.sha256(value.encode()).hexdigest()[:12]}]'


def redact(text: str) -> str:
    text = BEARER.sub('[CREDENTIAL_REDACTED]', text)
    text = FIELD.sub(lambda m: m[1] + '[FIELD_REDACTED]', text)
    text = EMAIL.sub('[EMAIL_REDACTED]', text)

    def ip(match):
        try:
            ipaddress.ip_address(match[0].split('%')[0])
        except ValueError:
            return '[IP_REDACTED]' if '.' in match[0] else match[0]
        return '[IP_REDACTED]'

    text = IP.sub(ip, text)
    text = PATH.sub(lambda m: _pseudonym('PATH', m[0]), text)
    text = HOST.sub(lambda m: _pseudonym('HOST', m[0]), text)
    return KEY.sub('[CREDENTIAL_REDACTED]', text)
