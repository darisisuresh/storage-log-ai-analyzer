from __future__ import annotations

import re
import json
import hashlib
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, asdict

from .models import Event, Finding
from .timestamps import normalize
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



def _ordered_events(db, events, diagnostics):
    db.execute('CREATE TABLE ordered_events (seq INTEGER PRIMARY KEY, stamp TEXT, payload TEXT)')
    db.execute('CREATE TABLE device_vendors (device TEXT PRIMARY KEY, vendor TEXT)')
    db.execute('CREATE TABLE clock_progress (device TEXT PRIMARY KEY, stamp TEXT)')
    for seq, event in enumerate(events):
        if event.timestamp and event.timestamp_original is None:
            event.timestamp_original = event.timestamp
            event.timestamp, event.timestamp_status = normalize(event.timestamp)
        identity = event.device or ('source:' + event.source)
        if event.timestamp:
            old = db.execute('SELECT stamp FROM clock_progress WHERE device=?', (identity,)).fetchone()
            if old and event.timestamp < old[0]:
                diagnostics['out_of_order_events'] = diagnostics.get('out_of_order_events', 0) + 1
            db.execute('INSERT OR REPLACE INTO clock_progress VALUES (?,?)', (identity, max(event.timestamp, old[0]) if old else event.timestamp))
        if event.device and event.vendor in {'pure', 'emc', 'hpe'}:
            key = event.device.casefold()
            old = db.execute('SELECT vendor FROM device_vendors WHERE device=?', (key,)).fetchone()
            value = event.vendor if not old or old[0] == event.vendor else 'unknown'
            db.execute('INSERT OR REPLACE INTO device_vendors VALUES (?,?)', (key, value))
        db.execute('INSERT INTO ordered_events VALUES (?,?,?)', (seq, event.timestamp, json.dumps(asdict(event))))
    db.execute('CREATE INDEX event_time_order ON ordered_events(stamp,seq)')
    for raw, in db.execute('SELECT payload FROM ordered_events ORDER BY stamp IS NULL, stamp, seq'):
        event = Event(**json.loads(raw))
        if event.device and (event.vendor == 'unknown' or event.vendor_source == 'same_device_history'):
            old = db.execute('SELECT vendor FROM device_vendors WHERE device=?', (event.device.casefold(),)).fetchone()
            if old and old[0] != 'unknown':
                event.vendor, event.vendor_source = old[0], 'same_device_history'
            elif old and event.vendor_source == 'same_device_history':
                event.vendor, event.vendor_source = 'unknown', 'conflicting_device_history'
        yield event


def _policy(rule, context, gap, target):
    if rule.rule_id.startswith('STO-') and context.get('service_impact') is True:
        return 'critical', 'confirmed_service_impact'
    if rule.rule_id.startswith('STO-') and context.get('redundancy') == 'lost':
        return 'critical', 'confirmed_redundancy_loss'
    if rule.rule_id == 'STO-001' and context.get('redundancy') == 'healthy' and context.get('service_impact') is False:
        return 'high', 'confirmed_healthy_redundancy'
    if rule.rule_id == 'STO-005' and target is not None and gap is not None and gap > target:
        return 'critical', 'rpo_target_exceeded'
    return rule.severity, 'rule_default'


def _gap(event, context, state):
    if state == 'RESOLVED':
        return 0.0
    measured = context.get('replication_lag_seconds')
    if measured is not None:
        return float(measured)
    stamp, success = _time(event.timestamp), _time(context.get('last_successful_replication'))
    if stamp and success:
        value = (datetime.fromisoformat(stamp) - datetime.fromisoformat(success)).total_seconds()
        return value if value >= 0 else None
    return None


def _evaluate(events, diagnostics, on_event, rpo_target_seconds):
    groups = {}
    rules = {rule.rule_id: rule for rule in RULES}
    with tempfile.TemporaryDirectory(prefix='storage-incidents-') as folder:
        with closing(sqlite3.connect(str(Path(folder) / 'incidents.db'))) as db, db:
            db.execute('PRAGMA cache_size=-4096')
            db.execute('PRAGMA temp_store=FILE')
            db.execute('CREATE TABLE incidents (rule TEXT, device TEXT, resource TEXT, state TEXT, count INTEGER, unique_count INTEGER, duplicates INTEGER, evidence TEXT, stamp TEXT, first_seen TEXT, last_seen TEXT, context TEXT, severity TEXT, basis TEXT, group_id TEXT, gap REAL, max_gap REAL, duration REAL, PRIMARY KEY(rule,device,resource))')
            db.execute('CREATE TABLE seen (fingerprint TEXT PRIMARY KEY)')
            for event in _ordered_events(db, events, diagnostics):
                if on_event:
                    on_event(event)
                for clause in CLAUSES.split(event.message):
                    for rule in RULES:
                        state = _state(rule, clause)
                        if state is None:
                            continue
                        clause_device, clause_resource = _identity({}, clause)
                        device = clause_device or event.device or ('source:' + event.source)
                        resource = clause_resource or (event.resource if len(CLAUSES.split(event.message)) == 1 else '')
                        if len(device) > 256:
                            device = 'identity-sha256:' + hashlib.sha256(device.encode()).hexdigest()
                        if len(resource) > 256:
                            resource = 'resource-sha256:' + hashlib.sha256(resource.encode()).hexdigest()
                        key = (rule.rule_id, device, resource)
                        old = db.execute('SELECT state,count,unique_count,duplicates,evidence,stamp,first_seen,last_seen,context,severity,basis,gap,max_gap,duration FROM incidents WHERE rule=? AND device=? AND resource=?', key).fetchone()
                        if old is None and state != 'OPEN':
                            continue
                        fingerprint = hashlib.sha256(json.dumps([*key, event.timestamp_original, event.timestamp, clause], ensure_ascii=True).encode()).hexdigest()
                        duplicate = db.execute('INSERT OR IGNORE INTO seen VALUES (?)', (fingerprint,)).rowcount == 0
                        if old and old[0] == 'RESOLVED' and state == 'OPEN':
                            duplicate = False
                        if duplicate:
                            diagnostics['duplicate_records'] = diagnostics.get('duplicate_records', 0) + 1
                        stamp = _time(event.timestamp)
                        final_state = old[0] if old and duplicate else state
                        if old and old[5] and not stamp and state == 'RESOLVED':
                            final_state = 'UNKNOWN'
                            diagnostics['unsequenced_recovery_events'] = diagnostics.get('unsequenced_recovery_events', 0) + 1
                        active_occurrence = state != 'RESOLVED'
                        count = (old[1] if old else 0) + active_occurrence
                        unique_count = (old[2] if old else 0) + (active_occurrence and not duplicate)
                        duplicates = (old[3] if old else 0) + (active_occurrence and duplicate)
                        evidence = json.loads(old[4]) if old else []
                        sample = f'{event.source}:{event.line}: [{device} {resource}] UTC={event.timestamp or "unknown"} original={event.timestamp_original or "unknown"} status={event.timestamp_status}: {clause[:240]}'[:1200]
                        if not duplicate and len(evidence) < 5:
                            evidence.append(sample)
                        elif old and final_state != old[0]:
                            evidence[-1] = sample
                        first = old[6] if old else stamp
                        last = old[7] if duplicate and old else stamp
                        context = json.loads(old[8]) if old and not (old[0] == 'RESOLVED' and state == 'OPEN') else {}
                        context.update(event.context)
                        if not old or (old[0] == 'RESOLVED' and state == 'OPEN'):
                            context['_cycle_start'] = stamp
                        gap = _gap(event, context, final_state) if rule.rule_id == 'STO-005' else None
                        max_gap = max([v for v in ((old[12] if old else None), gap) if v is not None], default=None)
                        cycle_start = context.get('_cycle_start')
                        duration = (datetime.fromisoformat(last) - datetime.fromisoformat(cycle_start)).total_seconds() if cycle_start and last else None
                        severity, basis = _policy(rule, context, gap, rpo_target_seconds)
                        if final_state == 'RESOLVED' and old:
                            severity, basis = old[9], old[10]
                        db.execute('INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (*key, final_state, count, unique_count, duplicates, json.dumps(evidence), stamp if not duplicate else old[5], first, last, json.dumps(context), severity, basis, context.get('protection_group'), gap, max_gap, duration))
            # Only explicit protection-group membership permits multi-drive escalation.
            for device, group_id in db.execute("SELECT device,group_id FROM incidents WHERE rule='STO-001' AND state!='RESOLVED' AND group_id IS NOT NULL GROUP BY device,group_id HAVING count(*)>1"):
                db.execute("UPDATE incidents SET severity='critical',basis='multiple_drives_same_group' WHERE rule='STO-001' AND device=? AND group_id=? AND state!='RESOLVED'", (device, group_id))
            for row in db.execute('SELECT rule,device,resource,state,count,unique_count,duplicates,evidence,first_seen,last_seen,severity,basis,gap,max_gap,duration FROM incidents ORDER BY rule,device,resource'):
                rid, device, resource, state, count, unique_count, duplicates, raw, first, last, severity, basis, gap, max_gap, duration = row
                rule = rules[rid]
                key = rid, state, severity, basis
                if key not in groups:
                    groups[key] = Finding(rid, severity, rule.category, rule.title, [], list(rule.recommendations), 0, state, 0, [], first, last, severity_basis=basis)
                finding = groups[key]
                finding.count += count
                finding.unique_event_count += unique_count
                finding.duplicate_count += duplicates
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
                for name, value in [('replication_gap_seconds', gap), ('max_replication_gap_seconds', max_gap), ('duration_seconds', duration)]:
                    if value is not None:
                        previous = getattr(finding, name)
                        setattr(finding, name, max(previous, value) if previous is not None else value)
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings = sorted(groups.values(), key=lambda f: (f.state == 'RESOLVED', order.get(f.severity, 9), f.rule_id, f.severity_basis))
    for index, finding in enumerate(findings, 1):
        finding.finding_ref = f'F{index}'
    return findings


def evaluate(events, *, diagnostics=None, on_event=None, rpo_target_seconds=None):
    try:
        return _evaluate(events, diagnostics if diagnostics is not None else {}, on_event, rpo_target_seconds)
    except sqlite3.Error as exc:
        raise RuntimeError(f'Incident state storage failed ({type(exc).__name__}); check temporary disk space') from None
