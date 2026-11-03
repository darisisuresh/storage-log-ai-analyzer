from __future__ import annotations

import json

from .models import AnalysisReport


def render(report: AnalysisReport, output_format: str) -> str:
    if output_format == 'json':
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    markdown = output_format == 'markdown'
    lines = (['# Storage Log Analysis', '', f'**Overall risk:** {report.risk.upper()}', f'**Events:** {report.event_count}', f'**Files:** {len(report.files)}', ''] if markdown else
             [f'Overall risk: {report.risk.upper()}', f'Events: {report.event_count} | Files: {len(report.files)}', f"Vendors: {', '.join(f'{k}={v}' for k, v in report.vendors.items()) or 'none'}", ''])
    if report.diagnostics:
        lines.extend(['Diagnostics: ' + json.dumps(report.diagnostics, sort_keys=True), ''])
    if not report.findings:
        lines.append('No known high-risk patterns were detected. This does not establish system health.')
    for index, item in enumerate(report.findings, 1):
        ref = item.finding_ref or f'F{index}'
        title = f'[{item.state}] [{item.severity.upper()}] {ref} {item.rule_id} {item.title}'
        lines.append(('### ' if markdown else '') + title)
        lines.append(f'{item.count} active-state event(s); {item.unique_event_count} unique; {item.duplicate_count} repeated; {item.incident_count} device/resource identities. Severity basis: {item.severity_basis}.')
        if item.first_seen or item.last_seen:
            lines.append(f'UTC range: {item.first_seen or "unknown"} to {item.last_seen or "unknown"}.')
        if item.replication_gap_seconds is not None:
            lines.append(f'Replication lag: {item.replication_gap_seconds:g}s; maximum observed lag: {item.max_replication_gap_seconds:g}s. This is not a measurement of data loss.')
        if item.duration_seconds is not None:
            lines.append(f'Observed current-cycle duration: {item.duration_seconds:g}s.')
        if markdown:
            lines.append('Evidence (local only):')
            lines.extend('- ' + evidence for evidence in item.evidence)
        actions = ['Historical incident resolved; verify recovery evidence.'] if item.state == 'RESOLVED' else item.recommendations
        lines.extend(('  - ' if not markdown else '- ') + action for action in actions)
        lines.append('')
    lines.append('AI status: ' + report.ai_status)
    if report.ai_error:
        lines.append('AI error: ' + report.ai_error)
    if report.ai_assessment:
        lines.extend(['', '## AI assessment' if markdown else 'AI assessment:', report.ai_assessment])
    return '\n'.join(lines)
