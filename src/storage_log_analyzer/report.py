from __future__ import annotations

import json

from .models import AnalysisReport


def render(report: AnalysisReport, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if output_format == "markdown":
        lines = ["# Storage Log Analysis", "", f"**Overall risk:** {report.risk.upper()}", f"**Events:** {report.event_count}", f"**Files:** {len(report.files)}", "", "## Findings", ""]
        if not report.findings:
            lines.append("No known high-risk patterns were detected.")
        for item in report.findings:
            lines.extend([f"### [{item.severity.upper()}] {item.title}", "", f"Rule `{item.rule_id}` matched {item.count} event(s).", "", "Evidence:"])
            lines.extend(f"- {evidence}" for evidence in item.evidence)
            lines.extend(["", "Recommended actions:"])
            lines.extend(f"- {action}" for action in item.recommendations)
            lines.append("")
        if report.ai_assessment:
            lines.extend(["## AI assessment", "", report.ai_assessment, ""])
        return "\n".join(lines)

    lines = [f"Overall risk: {report.risk.upper()}", f"Events: {report.event_count} | Files: {len(report.files)}", f"Vendors: {', '.join(f'{k}={v}' for k, v in report.vendors.items()) or 'none'}", ""]
    if not report.findings:
        lines.append("No known high-risk patterns were detected.")
    for item in report.findings:
        lines.append(f"[{item.severity.upper()}] {item.rule_id} {item.title} ({item.count} matches)")
        for action in item.recommendations:
            lines.append(f"  - {action}")
    if report.ai_assessment:
        lines.extend(["", "AI assessment:", report.ai_assessment])
    return "\n".join(lines)
