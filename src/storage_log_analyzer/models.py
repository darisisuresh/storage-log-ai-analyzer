from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Event:
    timestamp: str | None
    vendor: str
    product: str | None
    severity: str
    component: str
    message: str
    source: str
    line: int
    device: str | None = None
    resource: str = ""
    timestamp_original: str | None = None
    timestamp_status: str = "missing"
    format_error: str | None = None
    vendor_source: str = "unknown"
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    rule_id: str
    severity: str
    category: str
    title: str
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    count: int = 1
    state: str = "OPEN"
    incident_count: int = 1
    devices: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    unique_event_count: int = 0
    duplicate_count: int = 0
    severity_basis: str = "rule_default"
    replication_gap_seconds: float | None = None
    max_replication_gap_seconds: float | None = None
    duration_seconds: float | None = None
    finding_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AnalysisReport:
    files: list[str]
    event_count: int
    vendors: dict[str, int]
    severities: dict[str, int]
    findings: list[Finding]
    ai_assessment: str | None = None
    ai_status: str = "disabled"
    ai_error: str | None = None
    ai_details: dict[str, Any] | None = None
    diagnostics: dict[str, int] = field(default_factory=dict)

    @property
    def risk(self) -> str:
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        score = max((weights.get(item.severity, 0) for item in self.findings if item.state != "RESOLVED"), default=0)
        return {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(score, "informational")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["risk"] = self.risk
        return data
