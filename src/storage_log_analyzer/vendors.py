from __future__ import annotations

import re

VENDOR_HINTS = {
    "pure": ("pure storage", "flasharray", "purity", "pure1", "puredrive"),
    "emc": (
        "dell emc", "powerstore", "powermax", "vmax", "unity", "vnx", "isilon",
        "powerscale", "data domain", "symmetrix", "unisphere",
    ),
    "hpe": ("hewlett packard enterprise", "hpe", "alletra", "nimble", "primera", "3par", "msa"),
}

PRODUCT_HINTS = {
    "FlashArray": ("flasharray", "purity"),
    "PowerStore": ("powerstore",),
    "PowerMax": ("powermax", "vmax", "symmetrix"),
    "Unity": ("unity", "vnx"),
    "PowerScale": ("powerscale", "isilon"),
    "Data Domain": ("data domain", "ddboost"),
    "Alletra": ("alletra",),
    "Nimble": ("nimble",),
    "Primera/3PAR": ("primera", "3par"),
    "MSA": (" msa ", "msa2", "msa1"),
}

SEVERITY_PATTERNS = {
    "critical": re.compile(r"\b(critical|fatal|emergency|panic|sev[ -]?1)\b", re.I),
    "high": re.compile(r"\b(error|failed|failure|offline|degraded|sev[ -]?2)\b", re.I),
    "medium": re.compile(r"\b(warn(?:ing)?|attention|sev[ -]?3)\b", re.I),
    "low": re.compile(r"\b(info(?:rmational)?|notice|debug|cleared|healthy)\b", re.I),
}

COMPONENT_PATTERNS = {
    "drive": re.compile(r"\b(disk|drive|ssd|nvme|shelf)\b", re.I),
    "controller": re.compile(r"\b(controller|node|service processor|sp[ab])\b", re.I),
    "network": re.compile(r"\b(fc|fibre channel|iscsi|ethernet|port|link)\b", re.I),
    "volume": re.compile(r"\b(volume|lun|filesystem|file system|pool|aggregate)\b", re.I),
    "replication": re.compile(r"\b(replication|snapshot|remote copy|sync|protection group)\b", re.I),
    "security": re.compile(r"\b(login|authentication|audit|user|password|permission)\b", re.I),
}


def vendor_candidates(text: str) -> list[str]:
    lowered = text.lower()
    return [vendor for vendor, hints in VENDOR_HINTS.items() if any(hint in lowered for hint in hints)]


def detect_vendor(text: str) -> str:
    matches = vendor_candidates(text)
    return matches[0] if len(matches) == 1 else "unknown"


def detect_product(text: str) -> str | None:
    lowered = f" {text.lower()} "
    for product, hints in PRODUCT_HINTS.items():
        if any(hint in lowered for hint in hints):
            return product
    return None


def detect_severity(text: str) -> str:
    for severity, pattern in SEVERITY_PATTERNS.items():
        if pattern.search(text):
            return severity
    return "unknown"


def detect_component(text: str) -> str:
    for component, pattern in COMPONENT_PATTERNS.items():
        if pattern.search(text):
            return component
    return "system"
