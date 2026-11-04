"""Browser adapter: no server, API key, persistence, or alternative rule engine."""
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
import json

from storage_log_analyzer.ingest import ingest
from storage_log_analyzer.models import AnalysisReport
from storage_log_analyzer.report import render
from storage_log_analyzer.rules import evaluate


def analyze_browser(payload):
    options = payload['options']
    vendors, severities, diagnostics = Counter(), Counter(), Counter()
    count = 0

    def observed(event):
        nonlocal count
        count += 1
        vendors[event.vendor] += 1
        severities[event.severity] += 1
        diagnostics['timestamp_' + event.timestamp_status] += 1
        if event.timestamp_assumed_year is not None:
            diagnostics['timestamp_assumed_year'] += 1
        if event.format_error:
            diagnostics[event.format_error] += 1
        if not event.device:
            diagnostics['source_scoped_identity'] += 1
        if event.context.get('replication_timestamp_status'):
            diagnostics['replication_timestamp_' + event.context['replication_timestamp_status']] += 1
        if event.context.get('vendor_conflict'):
            diagnostics['vendor_conflicts'] += 1

    with TemporaryDirectory(prefix='browser-logs-') as directory:
        names = {}
        for index, file in enumerate(payload['files']):
            # Retain display names but never interpret visitor filenames as paths.
            suffix = Path(file['name']).suffix.lower()
            if suffix not in {'.log', '.txt', '.json', '.jsonl', '.csv'}:
                raise ValueError('Unsupported file format')
            path = Path(directory) / f'{index:03d}{suffix}'
            path.write_bytes(bytes(file['data']))
            names[str(path)] = file['name']
        try:
            _, events = ingest(Path(directory), options['vendor'], strict_format=options['strict'],
                               assume_timezone=options['timezone'], assume_year=options['year'])
            findings = evaluate(events, diagnostics=diagnostics, on_event=observed,
                                rpo_target_seconds=options['rpo'], correlation_window_seconds=options['window'])
        except (ValueError, RuntimeError) as error:
            message = str(error)
            for source, name in names.items():
                message = message.replace(source, name)
            raise ValueError(message) from None
        if not count:
            raise ValueError('The selected files contain no supported events. Choose a nonempty log file.')
        for index, finding in enumerate(findings, 1):
            finding.finding_ref = f'F{index}'
            for source, name in names.items():
                finding.evidence = [line.replace(source + ':', name + ':') for line in finding.evidence]
        report = AnalysisReport(list(names.values()), count, dict(vendors), dict(severities), findings,
                                diagnostics=dict(diagnostics))
        return json.dumps({'report': report.to_dict(), 'markdown': render(report, 'markdown')}, ensure_ascii=False)
