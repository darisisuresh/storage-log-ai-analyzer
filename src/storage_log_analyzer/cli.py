from __future__ import annotations

import argparse
import math
import os
import tempfile
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .ai import assess, build_ai_request
from .ingest import ingest
from .models import AnalysisReport
from .privacy import redact
from .report import render
from .rules import RULES, evaluate

SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _write_or_print(content: str, output: str | None, quiet=False) -> None:
    if output:
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=destination.parent, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(content.rstrip() + '\n')
            os.replace(temporary, destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        if not quiet:
            print(f"Report written to {destination}")
    else:
        print(content)


def _should_fail(risk: str, threshold: str) -> bool:
    return threshold != "never" and SEVERITY_RANK.get(risk, 0) >= SEVERITY_RANK[threshold]


def _scan_options(args):
    return {'strict_format': args.strict_format or getattr(args, 'strict', False),
            'assume_timezone': args.assume_timezone, 'assume_year': args.assume_year,
            'inventory': args.inventory, 'quarantine': args.quarantine}


def _diagnose(event, diagnostics):
    diagnostics['timestamp_' + event.timestamp_status] += 1
    diagnostics['vendor_' + event.vendor_source] += 1
    if not event.device:
        diagnostics['source_scoped_identity'] += 1
    if event.format_error:
        diagnostics[event.format_error] += 1
    if event.context.get('replication_timestamp_status'):
        diagnostics['replication_timestamp_' + event.context['replication_timestamp_status']] += 1
    if event.context.get('vendor_conflict'):
        diagnostics['vendor_conflicts'] += 1


def analyze_command(args: argparse.Namespace) -> int:
    try:
        files, events = ingest(Path(args.path), args.vendor, **_scan_options(args))
        vendors, severities, diagnostics = Counter(), Counter(), Counter()
        event_count = 0

        def observed(event):
            nonlocal event_count
            event_count += 1
            vendors[event.vendor] += 1
            severities[event.severity] += 1
            _diagnose(event, diagnostics)

        findings = evaluate(events, on_event=observed, diagnostics=diagnostics, rpo_target_seconds=args.rpo_target_seconds)
        if not files or not event_count:
            raise ValueError('No supported events found in the input')
        if args.min_severity:
            findings = [item for item in findings if SEVERITY_RANK[item.severity] >= SEVERITY_RANK[args.min_severity]]
        for index, finding in enumerate(findings, 1):
            finding.finding_ref = f'F{index}'
        report = AnalysisReport([str(path) for path in files], event_count, dict(vendors), dict(severities), findings, diagnostics=dict(diagnostics))
        if args.ai_preview:
            _write_or_print(json.dumps(build_ai_request(report, args.model), indent=2), args.output)
            return 0
        ai_failed = False
        if args.ai:
            report.ai_status = 'pending'
            if args.output:
                _write_or_print(render(report, args.format), args.output, quiet=True)
            try:
                report.ai_assessment = assess(report, args.model)
                report.ai_status = 'completed'
            except RuntimeError as exc:
                report.ai_status, report.ai_error, ai_failed = 'failed', str(exc), True
                print(f'AI unavailable: {exc}', file=sys.stderr)
        _write_or_print(render(report, args.format), args.output)
        return 1 if ai_failed else (2 if _should_fail(report.risk, args.fail_on) else 0)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


def summary_command(args: argparse.Namespace) -> int:
    try:
        files, events = ingest(Path(args.path), args.vendor, **_scan_options(args))
        vendors, products, severities, components = Counter(), Counter(), Counter(), Counter()
        event_count = 0
        diagnostics = Counter()
        for event in events:
            _diagnose(event, diagnostics)
            event_count += 1
            vendors[event.vendor] += 1
            products[event.product or "unknown"] += 1
            severities[event.severity] += 1
            components[event.component] += 1
        data = {"files": len(files), "events": event_count, "vendors": dict(vendors), "products": dict(products), "severities": dict(severities), "components": dict(components), "diagnostics": dict(diagnostics)}
        if args.format == "json":
            result = json.dumps(data, indent=2)
        else:
            result = "\n".join((f"Files: {len(files)}", f"Events: {event_count}", f"Vendors: {dict(vendors)}", f"Products: {dict(products)}", f"Severities: {dict(severities)}", f"Components: {dict(components)}", f"Diagnostics: {dict(diagnostics)}"))
        _write_or_print(result, args.output)
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def validate_command(args: argparse.Namespace) -> int:
    try:
        files, events = ingest(Path(args.path), args.vendor, **_scan_options(args))
        count = unknown_vendor = unknown_severity = 0
        diagnostics = Counter()
        for event in events:
            _diagnose(event, diagnostics)
            count += 1
            unknown_vendor += event.vendor == "unknown"
            unknown_severity += event.severity == "unknown"
        print(f"Files readable: {len(files)}")
        print(f"Events parsed: {count}")
        print(f"Unknown vendor: {unknown_vendor}")
        print(f"Unknown severity: {unknown_severity}")
        if not files or not count:
            print("Validation failed: no supported events found.", file=sys.stderr)
            return 1
        coverage = 100 * (count - unknown_vendor) / count
        print(f"Vendor recognition: {coverage:.1f}%")
        print(f"Diagnostics: {dict(diagnostics)}")
        return 2 if args.strict and (unknown_vendor or unknown_severity or any(diagnostics.get('timestamp_' + status) for status in ('invalid', 'missing_year', 'missing_time', 'missing_timezone', 'ambiguous_local_time'))) else 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        return 1


def redact_command(args: argparse.Namespace) -> int:
    source = Path(args.path)
    destination = Path(args.output)
    try:
        if not source.is_file():
            raise ValueError("redact currently accepts one file at a time")
        if source.resolve() == destination.resolve():
            raise ValueError("refusing to overwrite the source log; choose a different --output")
        from .ingest import MAX_RECORD
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with source.open(encoding="utf-8", errors="replace") as incoming:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent, delete=False) as outgoing:
                    temporary = Path(outgoing.name)
                    while line := incoming.readline(MAX_RECORD + 1):
                        if len(line) > MAX_RECORD:
                            raise ValueError("Input record exceeds 1 MiB")
                        outgoing.write(redact(line))
            os.replace(temporary, destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        print(f"Redacted copy written to {destination}")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def rules_command(args: argparse.Namespace) -> int:
    rules = [
        {"id": rule.rule_id, "severity": rule.severity, "category": rule.category, "title": rule.title}
        for rule in RULES if not args.category or rule.category == args.category
    ]
    if args.format == "json":
        print(json.dumps(rules, indent=2))
    else:
        for rule in rules:
            print(f"{rule['id']:<8} {rule['severity']:<8} {rule['category']:<16} {rule['title']}")
    return 0


def _seconds(value):
    try:
        result = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError('expected a nonnegative finite number') from None
    if not math.isfinite(result) or result < 0:
        raise argparse.ArgumentTypeError('expected a nonnegative finite number')
    return result


def _year(value):
    try:
        result = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('expected a year from 1 to 9999') from None
    if not 1 <= result <= 9999:
        raise argparse.ArgumentTypeError('expected a year from 1 to 9999')
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="storage-log-analyzer", description="Analyze storage logs locally with optional AI assistance")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze a file or directory")
    analyze.add_argument("path")
    analyze.add_argument("--vendor", choices=("auto", "pure", "emc", "hpe"), default="auto")
    analyze.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    analyze.add_argument("--output", "-o", help="write the report to a file")
    ai_group = analyze.add_mutually_exclusive_group()
    ai_group.add_argument("--ai", action="store_true", help="send aggregate finding counts to an AI model (no raw evidence)")
    ai_group.add_argument("--ai-preview", action="store_true", help="write the exact AI request JSON without contacting a provider")
    analyze.add_argument("--model", help="OpenAI model name; defaults to STORAGE_LOG_AI_MODEL or gpt-5-mini")
    analyze.add_argument("--min-severity", choices=("low", "medium", "high", "critical"), help="only include findings at or above this severity")
    analyze.add_argument("--fail-on", choices=("never", "low", "medium", "high", "critical"), default="high", help="return exit code 2 at or above this risk (default: high)")
    analyze.add_argument("--rpo-target-seconds", type=_seconds, help="escalate replication lag above this explicit target; no target is assumed")
    analyze.set_defaults(func=analyze_command)

    summary = subparsers.add_parser("summary", help="show vendor, product, severity, and component counts")
    summary.add_argument("path")
    summary.add_argument("--vendor", choices=("auto", "pure", "emc", "hpe"), default="auto")
    summary.add_argument("--format", choices=("text", "json"), default="text")
    summary.add_argument("--output", "-o")
    summary.set_defaults(func=summary_command)

    validate = subparsers.add_parser("validate", help="check whether logs can be parsed and recognized")
    validate.add_argument("path")
    validate.add_argument("--vendor", choices=("auto", "pure", "emc", "hpe"), default="auto")
    validate.add_argument("--strict", action="store_true", help="return exit code 2 for any unknown vendor or severity")
    validate.set_defaults(func=validate_command)

    redact_parser = subparsers.add_parser("redact", help="create a sanitized copy of a log file")
    redact_parser.add_argument("path")
    redact_parser.add_argument("--output", "-o", required=True)
    redact_parser.set_defaults(func=redact_command)

    rule_parser = subparsers.add_parser("rules", help="list built-in detection rules")
    rule_parser.add_argument("--category")
    rule_parser.add_argument("--format", choices=("text", "json"), default="text")
    rule_parser.set_defaults(func=rules_command)
    vendors = subparsers.add_parser("vendors", help="list supported vendor families")
    vendors.set_defaults(func=lambda _: (print("pure\nemc\nhpe") or 0))
    for command in (analyze, summary, validate):
        command.add_argument('--strict-format', action='store_true', help='reject malformed/non-object JSON Lines records with file and line number')
        command.add_argument('--quarantine', help='write rejected JSONL records to a private local file outside the input directory')
        command.add_argument('--inventory', help='JSON devices mapping with canonical per-device vendors')
        command.add_argument('--assume-timezone', default='UTC', help='IANA timezone for naive timestamps; assumption is recorded (default: UTC)')
        command.add_argument('--assume-year', type=_year, help='explicit year for RFC3164 syslog timestamps without a year')
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.func(args))
