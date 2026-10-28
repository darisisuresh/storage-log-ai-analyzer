from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Event, Finding


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    category: str
    title: str
    pattern: re.Pattern[str]
    recommendations: tuple[str, ...]


RULES = (
    Rule("STO-001", "critical", "availability", "Drive or media failure", re.compile(r"\b(disk|drive|ssd|nvme).{0,35}(failed|failure|fault|offline|unrecoverable)|\bmedia error\b", re.I), ("Identify the affected drive and protection state.", "Open a vendor support case if redundancy is reduced.")),
    Rule("STO-002", "high", "connectivity", "Storage path or port failure", re.compile(r"\b(path|fc port|iscsi|link).{0,35}(down|failed|offline|lost)|\bno active paths?\b", re.I), ("Verify multipathing and fabric health.", "Check switch, SFP, cable, and host HBA events.")),
    Rule("STO-003", "high", "capacity", "Capacity is critically high", re.compile(r"\b(9[0-9]|100)%\s*(full|used|utili[sz]ed)|\b(capacity|pool|filesystem).{0,35}(critical|full|exhausted)\b", re.I), ("Stop nonessential growth and confirm thin-provisioning risk.", "Reclaim or add capacity before writes are affected.")),
    Rule("STO-004", "high", "availability", "Controller or node degraded", re.compile(r"\b(controller|node|service processor|sp[ab]).{0,40}(failed|offline|degraded|panic|reboot)\b", re.I), ("Confirm peer controller takeover and host access.", "Collect diagnostics before changing controller state.")),
    Rule("STO-005", "high", "data-protection", "Replication or snapshot failure", re.compile(r"\b(replication|snapshot|remote copy|protection group).{0,45}(failed|stopped|broken|out of sync|error)\b", re.I), ("Measure the recovery-point gap.", "Restore replication and verify the latest usable recovery point.")),
    Rule("SEC-001", "high", "security", "Authentication failure", re.compile(r"\b(authentication|login|logon).{0,35}(failed|failure|denied|invalid)\b", re.I), ("Validate the source and targeted account.", "Rotate exposed credentials and review administrative audit logs.")),
    Rule("SEC-002", "critical", "security", "Possible ransomware or destructive activity", re.compile(r"\b(ransomware|mass delete|bulk delete|rapid encryption|snapshot deletion|snapshots? deleted|unusual file modifications)\b", re.I), ("Isolate affected hosts without deleting evidence.", "Protect immutable snapshots and activate the incident-response process.")),
    Rule("STO-006", "medium", "performance", "Latency or performance degradation", re.compile(r"\b(high|excessive|increased).{0,25}(latency|response time)|\b(latency|iops).{0,30}(threshold|degraded)\b", re.I), ("Correlate latency with host, fabric, and backend metrics.", "Compare against the normal workload baseline.")),
)


def evaluate(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        matched = [event for event in events if rule.pattern.search(event.message)]
        if not matched:
            continue
        evidence = [f"{event.source}:{event.line}: {event.message[:240]}" for event in matched[:5]]
        findings.append(Finding(rule.rule_id, rule.severity, rule.category, rule.title, evidence, list(rule.recommendations), len(matched)))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda finding: (order.get(finding.severity, 9), finding.rule_id))
