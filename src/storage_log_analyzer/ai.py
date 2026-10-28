from __future__ import annotations

import json
import os

from .models import AnalysisReport
from .privacy import redact


def assess(report: AnalysisReport, model: str | None = None) -> str:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is required when --ai is enabled")
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("AI support is not installed; run: pip install -e '.[ai]'") from exc

    payload = {
        "risk": report.risk,
        "event_count": report.event_count,
        "vendors": report.vendors,
        "severities": report.severities,
        "findings": [finding.to_dict() for finding in report.findings],
    }
    safe_payload = redact(json.dumps(payload, ensure_ascii=False))[:60_000]
    prompt = (
        "Analyze this redacted storage-system incident summary. Do not invent facts. "
        "Return: executive summary, prioritized observations, likely impact, immediate actions, "
        "and questions for the storage team. Clearly label uncertainty.\n\n" + safe_payload
    )
    client = OpenAI()
    response = client.responses.create(model=model or os.getenv("STORAGE_LOG_AI_MODEL", "gpt-5-mini"), input=prompt)
    return response.output_text
