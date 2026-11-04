"""Integration tests for the browser boundary around the unchanged rule engine."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('browser_analysis', Path(__file__).resolve().parents[1] / 'web' / 'analysis.py')
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class BrowserAdapterTests(unittest.TestCase):
    def analyze(self, rows, name='events.jsonl', **options):
        return json.loads(adapter.analyze_browser({'files': [{'name': name, 'data': list('\n'.join(json.dumps(row) for row in rows).encode())}], 'options': {'vendor': 'auto', 'timezone': 'UTC', 'year': None, 'rpo': None, 'window': 300, 'strict': True, **options}}))

    def test_same_device_correlation_and_display_filename(self):
        rows = [{'timestamp': '2026-11-04T12:00:00Z', 'device': 'array-a', 'message': 'controller A failed'}, {'timestamp': '2026-11-04T12:00:10Z', 'device': 'array-a', 'message': 'path 1 failed'}]
        data = self.analyze(rows, name='../../events.jsonl')
        self.assertEqual(data['report']['event_count'], 2)
        self.assertEqual({f['severity_basis'] for f in data['report']['findings']}, {'controller_path_correlation'})
        self.assertTrue(all('../../events.jsonl:' in f['evidence'][0] for f in data['report']['findings']))
        self.assertNotIn('browser-logs-', data['markdown'])

    def test_named_timezone_and_protected_recovery(self):
        rows = [{'timestamp': '2026-11-04T12:00:00', 'device': 'array-a', 'message': 'disk 1 failed', 'redundancy': 'healthy', 'service_impact': False}]
        data = self.analyze(rows, timezone='America/New_York')
        finding = data['report']['findings'][0]
        self.assertEqual(finding['severity'], 'high')
        self.assertEqual(finding['first_seen'], '2026-11-04T17:00:00.000000+00:00')

    def test_invalid_context_and_empty_input_fail_without_partial_report(self):
        with self.assertRaises(ValueError):
            self.analyze([{'message': 'disk 1 failed', 'risk_components': {'impact': 10}}])
        with self.assertRaises(ValueError):
            self.analyze([])
