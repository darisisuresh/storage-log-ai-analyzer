from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from .ai import assess
from .ingest import ingest
from .models import AnalysisReport
from .report import render
from .rules import evaluate


def analyze_command(args: argparse.Namespace) -> int:
    try:
        files, events = ingest(Path(args.path), args.vendor)
        report = AnalysisReport(
            files=[str(path) for path in files],
            event_count=len(events),
            vendors=dict(Counter(event.vendor for event in events)),
            severities=dict(Counter(event.severity for event in events)),
            findings=evaluate(events),
        )
        if args.ai:
            report.ai_assessment = assess(report, args.model)
        result = render(report, args.format)
        if args.output:
            Path(args.output).write_text(result + "\n", encoding="utf-8")
            print(f"Report written to {args.output}")
        else:
            print(result)
        return 2 if report.risk in {"critical", "high"} else 0
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="storage-log-analyzer", description="Analyze storage logs locally with optional AI assistance")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze a file or directory")
    analyze.add_argument("path")
    analyze.add_argument("--vendor", choices=("auto", "pure", "emc", "hpe"), default="auto")
    analyze.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    analyze.add_argument("--output")
    analyze.add_argument("--ai", action="store_true", help="send a redacted finding summary to an AI model")
    analyze.add_argument("--model", help="OpenAI model name; defaults to STORAGE_LOG_AI_MODEL or gpt-5-mini")
    analyze.set_defaults(func=analyze_command)
    vendors = subparsers.add_parser("vendors", help="list supported vendor families")
    vendors.set_defaults(func=lambda _: (print("pure\nemc\nhpe") or 0))
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.func(args))
