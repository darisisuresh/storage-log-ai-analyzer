import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from storage_log_analyzer.ai import build_ai_request
from storage_log_analyzer.cli import build_parser
from storage_log_analyzer.ingest import MAX_RECORD, ingest, iter_file, parse_file
from storage_log_analyzer.models import AnalysisReport, Finding
from storage_log_analyzer.privacy import redact
from storage_log_analyzer.rules import evaluate


class P0AcceptanceTests(unittest.TestCase):
    def scan(self, text, suffix='.log'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ('events' + suffix)
            path.write_text(text)
            return evaluate(iter_file(path))

    def test_review_failure_recovery_and_negative_status(self):
        findings = self.scan('2026-11-02 10:05 disk failure detected\n2026-11-02 10:15 disk failure cleared\n2026-11-02 10:20 no active disk failures\n')
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0].state, findings[0].count), ('RESOLVED', 1))
        self.assertEqual(AnalysisReport([], 3, {}, {}, findings).risk, 'informational')

    def test_negative_only_messages_create_no_incidents(self):
        for line in ('no active disk failures', 'drive not failed', 'no authentication failures', 'ransomware not detected', 'no replication failure'):
            with self.subTest(line=line):
                self.assertEqual(self.scan(line), [])

    def test_unrelated_negative_clause_does_not_suppress_failure(self):
        for line in ('no disk failures, controller failed', 'no disk failures but controller failed', 'no disk failures controller failed', 'disk failed with no further errors'):
            findings = self.scan(line)
            self.assertTrue(any(f.state == 'OPEN' for f in findings), line)

    def test_negated_examples_across_rule_families(self):
        for line in ('no controller failed', 'no capacity full', 'no replication failed', 'no high latency', 'no authentication failed', 'no snapshot deletion'):
            with self.subTest(line=line):
                self.assertEqual(self.scan(line), [])

    def test_redaction_failure_preserves_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            source, dest = Path(directory) / 'large.log', Path(directory) / 'safe.log'
            source.write_text('x' * (MAX_RECORD + 1))
            dest.write_text('previous-safe-output')
            args = build_parser().parse_args(['redact', str(source), '-o', str(dest)])
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(args.func(args), 1)
            self.assertEqual(dest.read_text(), 'previous-safe-output')
            self.assertEqual(len(list(Path(directory).iterdir())), 2)

    def test_csv_and_structured_json_preserve_device_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            for suffix, text in [('.csv', 'host,vendor,message\narray-a,pure,disk 7 failed\n'), ('.jsonl', '{"host":"array-a","vendor":"pure","message":"disk 7 failed"}\n')]:
                p = Path(directory) / ('events' + suffix)
                p.write_text(text)
                event = list(iter_file(p))[0]
                self.assertEqual((event.device, event.vendor, event.resource), ('array-a', 'pure', 'disk:7'))

    def test_no_active_paths_is_an_outage(self):
        self.assertEqual(self.scan('host=array-a no active paths')[0].state, 'OPEN')

    def test_negated_recovery_keeps_incident_open(self):
        result = self.scan('host=a disk 7 failed\nhost=a disk 7 failure not cleared')
        self.assertEqual(result[0].state, 'OPEN')

    def test_healthy_redundancy_does_not_clear_failed_drive(self):
        result = self.scan('host=a disk 7 failed with redundancy healthy')
        self.assertEqual(result[0].state, 'OPEN')

    def test_device_and_resource_boundaries(self):
        findings = self.scan('host=a disk 7 failed\nhost=b disk 7 failed\nhost=a disk 8 failed\nhost=a disk 7 failure cleared')
        states = {f.state: f for f in findings}
        self.assertEqual(states['OPEN'].incident_count, 2)
        self.assertEqual(states['RESOLVED'].incident_count, 1)
        self.assertIn('a/disk:7', states['RESOLVED'].devices)
        self.assertIn('b/disk:7', states['OPEN'].devices)
        self.assertIn('a/disk:8', states['OPEN'].devices)

    def test_structured_disk_id_correlates_with_text_resource(self):
        rows = [
            {'host': 'a', 'disk_id': 7, 'message': 'disk failure detected'},
            {'host': 'a', 'message': 'disk 7 failure cleared'},
        ]
        self.assertEqual(self.scan(json.dumps(rows), '.json')[0].state, 'RESOLVED')

    def test_unspecified_recovery_does_not_clear_identified_resource(self):
        findings = self.scan('host=a disk 7 failed\nhost=a disk failure cleared')
        self.assertEqual(findings[0].state, 'OPEN')

    def test_later_failure_reopens_incident(self):
        result = self.scan('host=a disk 7 failed\nhost=a disk 7 failure cleared\nhost=a disk 7 failed')
        self.assertEqual((result[0].state, result[0].count), ('OPEN', 2))

    def test_older_recovery_does_not_clear_newer_failure(self):
        rows = [
            {'timestamp': '2026-11-02T11:00:00Z', 'host': 'a', 'message': 'disk 7 failed'},
            {'timestamp': '2026-11-02T10:00:00Z', 'host': 'a', 'message': 'disk 7 failure cleared'},
        ]
        self.assertEqual(self.scan(json.dumps(rows), '.json')[0].state, 'OPEN')

    def test_acknowledged_and_recovering_remain_at_risk(self):
        for state, text in [('ACKNOWLEDGED', 'disk 7 failure acknowledged'), ('RECOVERING', 'disk 7 recovering')]:
            findings = self.scan('host=a disk 7 failed\nhost=a ' + text)
            self.assertEqual(findings[0].state, state)
            self.assertEqual(AnalysisReport([], 2, {}, {}, findings).risk, 'critical')

    def test_mixed_hosts_do_not_inherit_another_vendor(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'events.log'
            p.write_text('2026-11-02T10:00:00Z host-a Pure Storage disk 7 failed\n2026-11-02T10:01:00Z host-b disk 7 failed\n')
            events = list(iter_file(p))
            self.assertEqual([e.device for e in events], ['host-a', 'host-b'])
            self.assertEqual([e.vendor for e in events], ['pure', 'unknown'])

    def test_ai_schema_excludes_every_untrusted_field(self):
        secrets = ['2001:db8::1', 'hunter2', 'secret-token', 'client-x', '/customer/share', 'private-host']
        raw = ' '.join(secrets)
        finding = Finding(raw, 'high', raw, raw, [raw], [raw], devices=[raw])
        report = AnalysisReport([raw], 1, {raw: 1}, {raw: 1}, [finding])
        request = json.dumps(build_ai_request(report))
        for value in secrets:
            self.assertNotIn(value, request)
        payload = json.loads(build_ai_request(report)['input'].split('\n\n', 1)[1])
        self.assertFalse(payload['raw_evidence_included'])
        self.assertEqual(payload['findings'][0]['rule_id'], 'OTHER')

    def test_request_payload_stays_valid_without_mid_record_truncation(self):
        report = AnalysisReport([], 1, {}, {}, [Finding('STO-001', 'critical', 'x', 'x', ['x' * 100000]) for _ in range(100)])
        request = build_ai_request(report)
        payload = json.loads(request['input'].split('\n\n', 1)[1])
        self.assertEqual(payload['findings_omitted'], 60)
        self.assertLess(len(request['input']), 20000)

    def test_preview_never_calls_provider_and_matches_request(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'events.log'
            p.write_text('host=a disk 7 failed password=hunter2')
            args = build_parser().parse_args(['analyze', str(p), '--ai-preview'])
            with patch('storage_log_analyzer.cli.assess', side_effect=AssertionError('network called')):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(args.func(args), 0)
            request = json.loads(out.getvalue())
            findings = evaluate(iter_file(p))
            report = AnalysisReport([str(p)], 1, {'unknown': 1}, {'high': 1}, findings)
            self.assertEqual(request, build_ai_request(report))
            self.assertNotIn('hunter2', out.getvalue())

    def test_local_redaction_expands_known_sensitive_patterns(self):
        text = 'host=private-host user=admin tenant=client-x password=hunter2 Authorization: Bearer secret-token ip=2001:db8::1 path=/customers/client-x/share '
        result = redact(text)
        for value in ('private-host', 'admin', 'client-x', 'hunter2', 'secret-token', '2001:db8::1', '/customers'):
            self.assertNotIn(value, result)

    def test_json_arrays_and_envelopes_stream(self):
        for content in ('[{"message":"disk 7 failed"}]', '{"events":[{"message":"disk 7 failed"}],"metadata":"test"}'):
            self.assertEqual(self.scan(content, '.json')[0].rule_id, 'STO-001')

    def test_record_size_limit_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            for suffix, content in [('.log', 'x' * (MAX_RECORD + 1)), ('.json', json.dumps({'message': 'x' * (MAX_RECORD + 1)}))]:
                p = Path(directory) / ('events' + suffix)
                p.write_text(content)
                with self.assertRaisesRegex(ValueError, '1 MiB'):
                    list(iter_file(p))

    def test_ingestion_returns_lazy_events_and_capped_compatibility_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'events.log'
            p.write_text(('disk healthy\n') * 10001)
            files, events = ingest(p)
            self.assertEqual(files, [p])
            self.assertFalse(isinstance(events, list))
            with self.assertRaisesRegex(ValueError, 'iter_file'):
                parse_file(p)
            events.close()
