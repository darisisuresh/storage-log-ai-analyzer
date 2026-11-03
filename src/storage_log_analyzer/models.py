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

    @property
    def risk(self) -> str:
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        score = max((weights.get(item.severity, 0) for item in self.findings if item.state != "RESOLVED"), default=0)
        return {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(score, "informational")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["risk"] = self.risk
        return data
