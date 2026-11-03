from __future__ import annotations

import json
import os

from .models import AnalysisReport
from .rules import RULES


def assess(report: AnalysisReport, model: str | None = None) -> str:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is required when --ai is enabled")
    try:
        from openai import APIError, OpenAI
    except ImportError as exc:
        raise RuntimeError("AI support is not installed; run: pip install -e '.[ai]'") from exc

    request = build_ai_request(report, model)
    try:
        with OpenAI(timeout=60.0, max_retries=2) as client:
            response = client.responses.create(**request)
    except APIError as exc:
        # Avoid echoing request bodies or provider error text containing log data.
        raise RuntimeError(
            f"AI assessment failed ({type(exc).__name__}); check connectivity, credentials, "
            "model access, and API quota. Run without --ai for local analysis."
        ) from None
    if not response.output_text:
        raise RuntimeError("AI assessment returned no text; run without --ai for local analysis")
    return response.output_text


def build_ai_request(report: AnalysisReport, model: str | None = None) -> dict:
    """Only controlled fields cross the API boundary; raw evidence never does.

    The caller can serialize this exact request for a no-network preview.
    No arbitrary titles, counts-map keys, filenames, device names, or log text
    are copied into the request. Future fields must opt in here explicitly.
    """
    known = {rule.rule_id: rule for rule in RULES}
    states = {"OPEN", "ACKNOWLEDGED", "RECOVERING", "RESOLVED", "UNKNOWN"}

    def count(value):
        return value if type(value) is int and 0 <= value <= 10**18 else 0

    findings = []
    for index, finding in enumerate(report.findings[:40], 1):
        rule = known.get(finding.rule_id)
        findings.append({
            "finding_ref": f"F{index}",
            "rule_id": rule.rule_id if rule else "OTHER",
            "title": rule.title if rule else "Unrecognized local finding",
            "severity": rule.severity if rule else "unknown",
            "state": finding.state if finding.state in states else "UNKNOWN",
            "occurrence_count": count(finding.count),
            "incident_count": count(finding.incident_count),
        })
    payload = {
        "schema_version": 1,
        "event_count": count(report.event_count),
        "vendors": {key: count(report.vendors.get(key, 0)) for key in ('pure', 'emc', 'hpe', 'unknown')},
        "severities": {key: count(report.severities.get(key, 0)) for key in ('critical', 'high', 'medium', 'low', 'unknown')},
        "findings": findings,
        "raw_evidence_included": False,
        "findings_omitted": max(0, len(report.findings) - len(findings)),
    }
    prompt = (
        "Assess these aggregate local rule results only. No raw evidence or identities are supplied. "
        "Do not invent root causes or device details. Cite finding_ref values, distinguish resolved "
        "history from active findings, and clearly label uncertainty. Recommend verification, "
        "not automatic remediation.\n\n" + json.dumps(payload, ensure_ascii=True)
    )
    return {
        "model": model or os.getenv("STORAGE_LOG_AI_MODEL", "gpt-5-mini"),
        "input": prompt,
        "store": False,
    }
