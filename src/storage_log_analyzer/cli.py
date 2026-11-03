from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .ai import assess
from .ingest import ingest
from .models import AnalysisReport
from .privacy import redact
from .report import render
from .rules import RULES, evaluate

SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _write_or_print(content: str, output: str | None) -> None:
    if output:
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content.rstrip() + "\n", encoding="utf-8")
        print(f"Report written to {destination}")
    else:
        print(content)


def _should_fail(risk: str, threshold: str) -> bool:
    return threshold != "never" and SEVERITY_RANK.get(risk, 0) >= SEVERITY_RANK[threshold]


def analyze_command(args: argparse.Namespace) -> int:
    try:
        files, events = ingest(Path(args.path), args.vendor)
        if not files or not events:
            raise ValueError("No supported events found in the input")
        findings = evaluate(events)
        if args.min_severity:
            findings = [item for item in findings if SEVERITY_RANK[item.severity] >= SEVERITY_RANK[args.min_severity]]
        report = AnalysisReport(
            files=[str(path) for path in files],
            event_count=len(events),
            vendors=dict(Counter(event.vendor for event in events)),
            severities=dict(Counter(event.severity for event in events)),
            findings=findings,
        )
        if args.ai:
            report.ai_assessment = assess(report, args.model)
        result = render(report, args.format)
        _write_or_print(result, args.output)
        return 2 if _should_fail(report.risk, args.fail_on) else 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def summary_command(args: argparse.Namespace) -> int:
    try:
        files, events = ingest(Path(args.path), args.vendor)
        products = Counter(event.product or "unknown" for event in events)
        components = Counter(event.component for event in events)
        data = {
            "files": len(files),
            "events": len(events),
            "vendors": dict(Counter(event.vendor for event in events)),
            "products": dict(products),
            "severities": dict(Counter(event.severity for event in events)),
            "components": dict(components),
        }
        if args.format == "json":
            result = json.dumps(data, indent=2)
        else:
            result = "\n".join((
                f"Files: {data['files']}", f"Events: {data['events']}",
                f"Vendors: {dict(data['vendors'])}", f"Products: {dict(products)}",
                f"Severities: {dict(data['severities'])}", f"Components: {dict(components)}",
            ))
        _write_or_print(result, args.output)
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def validate_command(args: argparse.Namespace) -> int:
    try:
        files, events = ingest(Path(args.path), args.vendor)
        unknown_vendor = sum(event.vendor == "unknown" for event in events)
        unknown_severity = sum(event.severity == "unknown" for event in events)
        print(f"Files readable: {len(files)}")
        print(f"Events parsed: {len(events)}")
        print(f"Unknown vendor: {unknown_vendor}")
        print(f"Unknown severity: {unknown_severity}")
        if not files or not events:
            print("Validation failed: no supported events found.", file=sys.stderr)
            return 1
        coverage = 100 * (len(events) - unknown_vendor) / len(events)
        print(f"Vendor recognition: {coverage:.1f}%")
        return 2 if args.strict and (unknown_vendor or unknown_severity) else 0
    except (OSError, ValueError) as exc:
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
        content = source.read_text(encoding="utf-8", errors="replace")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(redact(content), encoding="utf-8")
        print(f"Redacted copy written to {destination}")
        return 0
    except (OSError, ValueError) as exc:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="storage-log-analyzer", description="Analyze storage logs locally with optional AI assistance")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze a file or directory")
    analyze.add_argument("path")
    analyze.add_argument("--vendor", choices=("auto", "pure", "emc", "hpe"), default="auto")
    analyze.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    analyze.add_argument("--output", "-o", help="write the report to a file")
    analyze.add_argument("--ai", action="store_true", help="send a redacted finding summary to an AI model")
    analyze.add_argument("--model", help="OpenAI model name; defaults to STORAGE_LOG_AI_MODEL or gpt-5-mini")
    analyze.add_argument("--min-severity", choices=("low", "medium", "high", "critical"), help="only include findings at or above this severity")
    analyze.add_argument("--fail-on", choices=("never", "low", "medium", "high", "critical"), default="high", help="return exit code 2 at or above this risk (default: high)")
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
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.func(args))
