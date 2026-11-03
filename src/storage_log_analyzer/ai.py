from __future__ import annotations

import json
import os

from .models import AnalysisReport
from .rules import RULES

STATES = {'OPEN', 'ACKNOWLEDGED', 'RECOVERING', 'RESOLVED', 'UNKNOWN'}
SEVERITIES = {'critical', 'high', 'medium', 'low', 'unknown'}
BASES = {'rule_default', 'confirmed_service_impact', 'confirmed_redundancy_loss', 'confirmed_healthy_redundancy', 'rpo_target_exceeded', 'multiple_drives_same_group'}
OBSERVATIONS = {'active_rule_match', 'resolved_rule_history', 'insufficient_context'}
UNCERTAINTIES = {'aggregate_only', 'identity_omitted', 'root_cause_unverified'}


def _payload(report):
    known = {rule.rule_id: rule for rule in RULES}

    def count(value):
        return value if type(value) is int and 0 <= value <= 10**18 else 0

    findings = []
    for index, finding in enumerate(report.findings[:40], 1):
        rule = known.get(finding.rule_id)
        rid = rule.rule_id if rule else 'OTHER'
        findings.append({
            'finding_ref': f'F{index}',
            'evidence_refs': [f'F{index}'],
            'rule_id': rid,
            'title': rule.title if rule else 'Unrecognized local finding',
            'severity': finding.severity if finding.severity in SEVERITIES else 'unknown',
            'severity_basis': finding.severity_basis if finding.severity_basis in BASES else 'rule_default',
            'state': finding.state if finding.state in STATES else 'UNKNOWN',
            'occurrence_count': count(finding.count),
            'incident_count': count(finding.incident_count),
            'duplicate_count': count(finding.duplicate_count),
            'allowed_action_codes': ([] if finding.state == 'RESOLVED' else ([f'{rid}:A{i}' for i in range(1, len(rule.recommendations) + 1)] if rule else ['OTHER:A1'])),
        })
    return {
        'schema_version': 2,
        'event_count': count(report.event_count),
        'vendors': {key: count(report.vendors.get(key, 0)) for key in ('pure', 'emc', 'hpe', 'unknown')},
        'severities': {key: count(report.severities.get(key, 0)) for key in ('critical', 'high', 'medium', 'low', 'unknown')},
        'findings': findings,
        'raw_evidence_included': False,
        'findings_omitted': max(0, len(report.findings) - len(findings)),
    }


def _schema(payload):
    refs = [f['finding_ref'] for f in payload['findings']] or ['NONE']
    actions = sorted({a for f in payload['findings'] for a in f['allowed_action_codes']}) or ['OTHER:A1']
    props = {
        'finding_ref': {'type': 'string', 'enum': refs},
        'evidence_refs': {'type': 'array', 'items': {'type': 'string', 'enum': refs}, 'minItems': 1, 'maxItems': 1},
        'observation_code': {'type': 'string', 'enum': sorted(OBSERVATIONS)},
        'action_codes': {'type': 'array', 'items': {'type': 'string', 'enum': actions}, 'maxItems': 2},
        'confidence': {'type': 'string', 'enum': ['not_calibrated']},
        'uncertainty_codes': {'type': 'array', 'items': {'type': 'string', 'enum': sorted(UNCERTAINTIES)}, 'minItems': 3, 'maxItems': 3},
        'requires_operator_approval': {'type': 'boolean', 'enum': [True]},
        'validation_required': {'type': 'boolean', 'enum': [True]},
    }
    return {'type': 'object', 'properties': {'items': {'type': 'array', 'maxItems': 8, 'items': {'type': 'object', 'properties': props, 'required': list(props), 'additionalProperties': False}}}, 'required': ['items'], 'additionalProperties': False}


def build_ai_request(report: AnalysisReport, model: str | None = None) -> dict:
    payload = _payload(report)
    try:
        budget = int(os.getenv('STORAGE_LOG_AI_MAX_OUTPUT_TOKENS', '4096'))
    except ValueError:
        raise RuntimeError('STORAGE_LOG_AI_MAX_OUTPUT_TOKENS must be an integer from 256 to 8192') from None
    if not 256 <= budget <= 8192:
        raise RuntimeError('STORAGE_LOG_AI_MAX_OUTPUT_TOKENS must be from 256 to 8192')
    prompt = (
        'Prioritize up to eight of these local aggregate rule findings. No raw evidence or identities are provided. '
        'Return only the supplied finding/evidence references and permitted observation/action codes. '
        'Use resolved_rule_history only for RESOLVED state; use active_rule_match for active state, or insufficient_context. '
        'All items require the three uncertainty codes and human validation. Confidence is not calibrated. '
        'No root cause, device identity, unsupported claims, or automatic remediation may be added.\n\n'
        + json.dumps(payload, ensure_ascii=True)
    )
    return {
        'model': model or os.getenv('STORAGE_LOG_AI_MODEL', 'gpt-5-mini'),
        'input': prompt,
        'store': False,
        'max_output_tokens': budget,
        'text': {'format': {'type': 'json_schema', 'name': 'storage_assessment', 'strict': True, 'schema': _schema(payload)}},
    }


def validate_assessment(value, report):
    findings = {f['finding_ref']: f for f in _payload(report)['findings']}
    if not isinstance(value, dict) or set(value) != {'items'} or not isinstance(value['items'], list) or len(value['items']) > 8:
        raise ValueError('invalid assessment structure')
    if findings and not value['items']:
        raise ValueError('assessment omitted every finding')
    seen = set()
    fields = {'finding_ref', 'evidence_refs', 'observation_code', 'action_codes', 'confidence', 'uncertainty_codes', 'requires_operator_approval', 'validation_required'}
    for item in value['items']:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError('unsupported assessment fields')
        ref = item['finding_ref']
        if not isinstance(ref, str) or ref not in findings or ref in seen:
            raise ValueError('unknown or repeated finding reference')
        seen.add(ref)
        fact = findings[ref]
        if item['evidence_refs'] != [ref]:
            raise ValueError('evidence does not support this finding')
        code = item['observation_code']
        expected = ('resolved_rule_history' if fact['state'] == 'RESOLVED' else ('insufficient_context' if fact['state'] == 'UNKNOWN' else 'active_rule_match'))
        if code not in (expected, 'insufficient_context'):
            raise ValueError('observation contradicts local state')
        actions = item['action_codes']
        if not isinstance(actions, list) or len(actions) > 2 or any(not isinstance(a, str) or a not in fact['allowed_action_codes'] for a in actions) or len(actions) != len(set(actions)):
            raise ValueError('unsupported recommendation')
        uncertainties = item['uncertainty_codes']
        if not isinstance(uncertainties, list) or len(uncertainties) != 3 or any(not isinstance(v, str) for v in uncertainties) or set(uncertainties) != UNCERTAINTIES:
            raise ValueError('required uncertainty is missing')
        if item['confidence'] != 'not_calibrated' or item['requires_operator_approval'] is not True or item['validation_required'] is not True:
            raise ValueError('unsupported confidence or remediation claim')
    return value


def _render(value, report):
    known = {rule.rule_id: rule for rule in RULES}
    facts = {f['finding_ref']: f for f in _payload(report)['findings']}
    lines = ['Structured AI prioritization of local rule facts; confidence is not calibrated.']
    for item in value['items']:
        fact = facts[item['finding_ref']]
        lines.append(f"{item['finding_ref']} — {fact['title']} ({fact['state']}); {item['observation_code']}.")
        rule = known.get(fact['rule_id'])
        for action in item['action_codes']:
            index = int(action.split(':A')[1]) - 1
            lines.append('  - ' + (rule.recommendations[index] if rule else 'Verify the local finding and original evidence.'))
        lines.append('  Evidence: ' + ', '.join(item['evidence_refs']) + '; aggregate only; root cause unverified; operator validation required.')
    return '\n'.join(lines)


def assess(report: AnalysisReport, model: str | None = None) -> str:
    if not os.getenv('OPENAI_API_KEY'):
        raise RuntimeError('OPENAI_API_KEY is required when --ai is enabled')
    try:
        from openai import APIError, OpenAI
    except ImportError as exc:
        raise RuntimeError("AI support is not installed; run: pip install -e '.[ai]'") from exc
    request = build_ai_request(report, model)
    try:
        with OpenAI(timeout=60.0, max_retries=2) as client:
            response = client.responses.create(**request)
    except (APIError, ValueError, TypeError, OSError) as exc:
        raise RuntimeError(f'AI assessment failed ({type(exc).__name__}); check connectivity, credentials, model access, and API quota. Local findings are preserved.') from None
    if getattr(response, 'status', 'completed') != 'completed':
        raise RuntimeError('AI response incomplete or token budget exhausted; local findings are preserved')
    if not isinstance(response.output_text, str) or not response.output_text:
        raise RuntimeError('AI assessment returned no text; local findings are preserved')
    if len(response.output_text) > 65536:
        raise RuntimeError('AI assessment exceeded the response size limit; local findings are preserved')
    try:
        details = validate_assessment(json.loads(response.output_text), report)
    except (ValueError, TypeError, KeyError, RecursionError):
        raise RuntimeError('AI assessment rejected: invalid schema, unsupported references, or unsupported claim. Local findings are preserved.') from None
    report.ai_details = details
    return _render(details, report)
