from __future__ import annotations

import re
import json
import hashlib
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass

from .models import Finding
from .ingest import _identity


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



SUBJECTS = {
    "STO-001": r"\b(disk|drive|ssd|nvme|media)\b",
    "STO-002": r"\b(path|port|iscsi|link)\b",
    "STO-003": r"\b(capacity|pool|filesystem)\b",
    "STO-004": r"\b(controller|node|service processor|spa|spb)\b",
    "STO-005": r"\b(replication|snapshot|remote copy|protection group)\b",
    "STO-006": r"\b(latency|iops|performance|response time)\b",
    "SEC-001": r"\b(authentication|login|logon)\b",
    "SEC-002": r"\b(ransomware|mass delete|bulk delete|encryption|snapshot deletion)\b",
}
NEGATIVE = re.compile(r"\b(?:no|without|zero)\s+(?:(?:high|excessive|increased)\s+)?(?:latency|performance degradation|response time degradation|rapid encryption|mass delete|bulk delete)\b|\b(?:no|without|zero)\s+(?:(?:active|current|reported|known|new|further|detected)\s+){0,3}(?:(?:disk|drive|controller|node|path|port|authentication|login|replication|snapshot|capacity|pool|filesystem|media|ransomware)\s+){0,2}(?:failures?|failed|errors?|faults?|ransomware|degradation|outages?|issues?|full|exhausted|snapshot deletion|deletion|active paths?)\b|\b(?:not|never)\s+(?:failed|failing|offline|degraded|full|exhausted|broken|detected)\b|\b(?:failure|failed|error)\s*[:=]\s*(?:false|no|0)\b", re.I)
RECOVERY = re.compile(r"\b(cleared|resolved|recovered|restored|healthy|normal|online|resync completed|resync successful)\b", re.I)
NEGATED_RECOVERY = re.compile(r"\b(?:not|never|no longer)\s+(?:yet\s+)?(?:cleared|resolved|recovered|restored|healthy|normal|online)\b", re.I)
CLAUSES = re.compile(r"[;,]|\b(?:but|and)\b|[.!?]\s+", re.I)


def _state(rule, clause):
    match = rule.pattern.search(clause)
    subject = re.search(SUBJECTS[rule.rule_id], clause, re.I)
    if not match and not subject:
        return None
    negative = NEGATIVE.search(clause)
    if negative and (re.search(SUBJECTS[rule.rule_id], negative[0], re.I) or negative[0].lower().startswith(("not ", "never "))):
        # 'no active paths' is an outage, not a healthy statement.
        if re.search(r"\bno active paths?\b", clause, re.I) and rule.rule_id == 'STO-002':
            return 'OPEN'
        return 'RESOLVED'
    if RECOVERY.search(clause) and not NEGATED_RECOVERY.search(clause) and (not match or re.search(r'\b(cleared|resolved|recovered|restored|online)\b', clause, re.I)):
        return 'RESOLVED'
    if re.search(r"\b(recovering|resyncing|rebuilding)\b", clause, re.I) and subject:
        return 'RECOVERING'
    if re.search(r"\backnowledged\b", clause, re.I) and subject:
        return 'ACKNOWLEDGED'
    return 'OPEN' if match else None


def _time(value):
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        # Naive timestamps are not silently interpreted as a local timezone.
        return stamp.astimezone(timezone.utc).isoformat() if stamp.tzinfo else None
    except ValueError:
        return None


def _evaluate(events):
    """Incremental detection with a disk-backed per-device incident state table.

    Output is aggregated by rule/state, with at most five local evidence/device
    samples per group. RAM and evidence do not grow with the number of events.
    """
    groups = {}
    rules = {rule.rule_id: rule for rule in RULES}
    with tempfile.TemporaryDirectory(prefix='storage-incidents-') as folder:
        with closing(sqlite3.connect(str(Path(folder) / 'incidents.db'))) as db, db:
            db.execute('PRAGMA cache_size=-4096')
            db.execute('PRAGMA temp_store=FILE')
            db.execute('CREATE TABLE incidents (rule TEXT, device TEXT, resource TEXT, state TEXT, count INTEGER, evidence TEXT, stamp TEXT, first_seen TEXT, last_seen TEXT, PRIMARY KEY(rule,device,resource))')
            for event in events:
                for clause in CLAUSES.split(event.message):
                    for rule in RULES:
                        state = _state(rule, clause)
                        if state is None:
                            continue
                        clause_device, clause_resource = _identity({}, clause)
                        device = clause_device or event.device or ('source:' + event.source)
                        resource = clause_resource or (event.resource if len(CLAUSES.split(event.message)) == 1 else '')
                        if len(device) > 256:
                            device = "identity-sha256:" + hashlib.sha256(device.encode()).hexdigest()
                        if len(resource) > 256:
                            resource = "resource-sha256:" + hashlib.sha256(resource.encode()).hexdigest()
                        key = (rule.rule_id, device, resource)
                        old = db.execute('SELECT state,count,evidence,stamp,first_seen,last_seen FROM incidents WHERE rule=? AND device=? AND resource=?', key).fetchone()
                        if old is None and state == 'RESOLVED':
                            continue
                        # Recovery of a different/unspecified resource never clears a known one.
                        stamp = _time(event.timestamp)
                        final_state = state
                        if old and stamp and old[3] and stamp < old[3]:
                            final_state = old[0]
                        count = (old[1] if old else 0) + (state != 'RESOLVED')
                        evidence = json.loads(old[2]) if old else []
                        sample = f'{event.source}:{event.line}: [{device} {resource}] {(event.timestamp or "timestamp unknown")[:128]}: {clause[:240]}'[:1200]
                        if len(evidence) < 5:
                            evidence.append(sample)
                        elif final_state != old[0]:
                            evidence[-1] = sample
                        first_seen = old[4] if old else (event.timestamp or "")[:128] or None
                        last_seen = old[5] if old and final_state != state else (event.timestamp or "")[:128] or None
                        db.execute('INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?,?)', (*key, final_state, count, json.dumps(evidence), (old[3] if old and final_state != state else stamp), first_seen, last_seen))
            for row in db.execute('SELECT rule,device,resource,state,count,evidence,first_seen,last_seen FROM incidents ORDER BY rule,device,resource'):
                rid, device, resource, state, count, raw, first, last = row
                rule = rules[rid]
                key = rid, state
                if key not in groups:
                    groups[key] = Finding(rid, rule.severity, rule.category, rule.title, [], list(rule.recommendations), 0, state, 0, [], first, last)
                finding = groups[key]
                finding.count += count
                finding.incident_count += 1
                if len(finding.devices) < 5:
                    finding.devices.append(device + ('/' + resource if resource else ''))
                for sample in json.loads(raw):
                    if len(finding.evidence) < 5:
                        finding.evidence.append(sample)
                if first and (not finding.first_seen or first < finding.first_seen):
                    finding.first_seen = first
                if last and (not finding.last_seen or last > finding.last_seen):
                    finding.last_seen = last
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    return sorted(groups.values(), key=lambda f: (f.state == 'RESOLVED', order.get(f.severity, 9), f.rule_id))


def evaluate(events):
    try:
        return _evaluate(events)
    except sqlite3.Error as exc:
        raise RuntimeError(f"Incident state storage failed ({type(exc).__name__}); check temporary disk space") from None
