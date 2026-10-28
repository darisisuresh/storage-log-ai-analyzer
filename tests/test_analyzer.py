import json
import tempfile
import unittest
from pathlib import Path

from storage_log_analyzer.ingest import parse_file
from storage_log_analyzer.cli import _should_fail
from storage_log_analyzer.privacy import redact
from storage_log_analyzer.rules import evaluate
from storage_log_analyzer.vendors import detect_vendor


class AnalyzerTests(unittest.TestCase):
    def test_vendor_detection(self):
        self.assertEqual(detect_vendor("Pure Storage FlashArray Purity alert"), "pure")
        self.assertEqual(detect_vendor("Dell EMC PowerStore notification"), "emc")
        self.assertEqual(detect_vendor("HPE Alletra system event"), "hpe")

    def test_parse_json_and_find_drive_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text(json.dumps([{"timestamp": "2026-01-01T00:00:00Z", "severity": "critical", "message": "HPE Alletra drive 7 failed"}]))
            events = parse_file(path)
            findings = evaluate(events)
        self.assertEqual(events[0].vendor, "hpe")
        self.assertEqual(events[0].severity, "critical")
        self.assertIn("STO-001", {finding.rule_id for finding in findings})

    def test_redaction(self):
        result = redact("admin@example.com connected from 10.2.3.4 serial=ABC123456")
        self.assertNotIn("admin@example.com", result)
        self.assertNotIn("10.2.3.4", result)
        self.assertNotIn("ABC123456", result)

    def test_mixed_vendor_file_detects_each_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mixed.log"
            path.write_text("Pure Storage FlashArray warning\nDell EMC PowerStore error\nHPE Alletra critical\n")
            events = parse_file(path)
        self.assertEqual([event.vendor for event in events], ["pure", "emc", "hpe"])

    def test_failure_threshold(self):
        self.assertTrue(_should_fail("critical", "high"))
        self.assertFalse(_should_fail("medium", "high"))
        self.assertFalse(_should_fail("critical", "never"))


if __name__ == "__main__":
    unittest.main()
