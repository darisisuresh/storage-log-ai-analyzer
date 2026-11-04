from __future__ import annotations

import hashlib
import hmac
import json
import secrets
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


# Normalize vendor spellings such as hostName, host_name, and host-name.
IDENTITY_FIELDS = {
    'host', 'hostname', 'hostid', 'device', 'deviceid', 'devicename',
    'array', 'arrayid', 'arrayname', 'serial', 'serialnumber', 'servicetag',
    'wwn', 'wwpn', 'wwnn', 'iqn', 'naa', 'user', 'username', 'userid',
    'customer', 'customerid', 'customername', 'tenant', 'tenantid', 'tenantname',
    'share', 'sharename', 'smbshare', 'nfsshare', 'path', 'filepath',
    'ip', 'ipaddress', 'ipv4', 'ipv6', 'address',
}
CREDENTIAL_FIELDS = {
    'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'accesskey',
    'authorization', 'cookie', 'clientsecret', 'accesskeyid', 'secretaccesskey',
    'sessiontoken', 'accesstoken', 'refreshtoken', 'privatekey',
}
VENDOR_ID = re.compile(r"\b(?:naa\.[a-f0-9]+|(?:[a-f0-9]{2}:){7}[a-f0-9]{2}|iqn\.\d{4}-\d{2}\.[^\s,;]+)\b", re.I)
EXTENDED_FIELD = re.compile(
    r"(?i)([\"']?\b(?:" + '|'.join(
        re.escape(k) for k in sorted(IDENTITY_FIELDS | CREDENTIAL_FIELDS, key=len, reverse=True)
    ) + r")[\"']?\s*[:=]\s*)(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;}]+)"
)


def _normal(key):
    return re.sub(r'[^a-z0-9]', '', key.lower())


class Redactor:
    """One local export session; aliases correlate without publishing reusable hashes.

    allowed_values preserves exact identity values only, never credentials.
    sensitive_fields extends the built-in schema for vendor-specific field names.
    Neither option changes the aggregate-only AI boundary.
    """

    def __init__(self, *, allowed_values=(), sensitive_fields=()):
        self.allowed_values = frozenset(allowed_values)
        self.sensitive_fields = IDENTITY_FIELDS | {_normal(k) for k in sensitive_fields}
        self._key = secrets.token_bytes(32)

    def _alias(self, kind, value):
        value = str(value)
        if value in self.allowed_values:
            return value
        digest = hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()[:16]
        return f'[{kind}_{digest}]'

    def redact_value(self, value, field=''):
        key = _normal(field)
        if key in CREDENTIAL_FIELDS or any(x in key for x in ('password', 'secret', 'token', 'credential')):
            return '[CREDENTIAL_REDACTED]'
        if key in self.sensitive_fields:
            return self._alias('IDENTITY', json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value)
        if isinstance(value, dict):
            return {k: self.redact_value(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact_value(v, field) for v in value]
        return self._text(value) if isinstance(value, str) else value

    def _text(self, text):
        text = BEARER.sub('[CREDENTIAL_REDACTED]', text)

        def field(match):
            key = _normal(re.split(r'[:=]', match[1], maxsplit=1)[0].strip(" \"'"))
            value = match[2].strip("\"'")
            return match[1] + str(self.redact_value(value, key))

        text = EXTENDED_FIELD.sub(field, text)
        text = FIELD.sub(field, text)
        text = EMAIL.sub(lambda m: self._alias('EMAIL', m[0]), text)
        text = VENDOR_ID.sub(lambda m: self._alias('IDENTITY', m[0]), text)
        text = IP.sub(lambda m: self._alias('IP', m[0]) if _is_ip(m[0]) else m[0], text)
        text = PATH.sub(lambda m: self._alias('PATH', m[0]), text)
        text = HOST.sub(lambda m: self._alias('HOST', m[0]), text)
        return KEY.sub('[CREDENTIAL_REDACTED]', text)

    def redact(self, text: str) -> str:
        try:
            value = json.loads(text)
        except (ValueError, RecursionError):
            return self._text(text)
        return json.dumps(self.redact_value(value), ensure_ascii=True) + ('\n' if text.endswith('\n') else '')


def _is_ip(value):
    try:
        ipaddress.ip_address(value.split('%')[0])
        return True
    except ValueError:
        return '.' in value


def redact(text: str) -> str:
    return Redactor().redact(text)
