"""P1-6/P1-7 regression cases, including uncertainty and false-correlation guards."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from storage_log_analyzer.ai import build_ai_request
from storage_log_analyzer.cli import build_parser
from storage_log_analyzer.impact import components, score
from storage_log_analyzer.ingest import iter_file
from storage_log_analyzer.models import AnalysisReport, Event
from storage_log_analyzer.report import render
from storage_log_analyzer.rules import evaluate
from storage_log_analyzer.timestamps import details, normalize


class TimeImpactTests(unittest.TestCase):
    def row(self, time='2026-11-02T10:00:00Z', message='disk 7 failed', **fields):
        return {'timestamp': time, 'host': 'array-a', 'vendor': 'pure', 'severity': 'high', 'message': message, **fields}

    def scan(self, rows, **options):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.json'
            path.write_text(json.dumps(rows))
            return evaluate(iter_file(path), **options)

    def test_spaced_offset_is_not_dropped_from_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.log'
            path.write_text('2026-11-02 10:00:00 +05:30 host=array-a disk 7 failed\n')
            event = next(iter_file(path))
            self.assertEqual(event.timestamp, '2026-11-02T04:30:00.000000+00:00')
            self.assertEqual(event.timestamp_original, '2026-11-02 10:00:00 +05:30')
            self.assertEqual(event.timezone_original, '+05:30')
            self.assertIsNone(event.timezone_assumed)

    def test_named_timezone_metadata_is_preserved_and_applied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.json'
            path.write_text(json.dumps(self.row('2026-11-02 10:00:00', timezone='America/New_York')))
            event = next(iter_file(path))
            self.assertEqual(event.timestamp, '2026-11-02T15:00:00.000000+00:00')
            self.assertEqual(event.timezone_original, 'America/New_York')
            self.assertIsNone(event.timezone_assumed)
            self.assertEqual(event.timestamp_status, 'valid')

    def test_timezone_policy_is_marked_as_assumed(self):
        clock = details('2026-11-02T10:00:00', 'America/New_York')
        self.assertIsNone(clock.original_timezone)
        self.assertEqual(clock.assumed_timezone, 'America/New_York')
        self.assertEqual(clock.status, 'assumed_timezone')

    def test_yearless_syslog_records_year_assumption(self):
        clock = details('Nov 2 10:00:00', assume_year=2026)
        self.assertEqual(clock.assumed_year, 2026)
        self.assertEqual(clock.assumed_timezone, 'UTC')

    def test_date_only_formats_never_fabricate_midnight(self):
        for value in ['20261102', '2026-11-02']:
            self.assertEqual(normalize(value), (None, 'missing_time'))
        self.assertEqual(normalize('20260230'), (None, 'invalid'))

    def test_negative_epoch_milliseconds(self):
        self.assertEqual(normalize(-1700000000000)[0], normalize(-1700000000)[0])
        self.assertEqual(normalize('-1700000000000')[0], normalize(-1700000000)[0])

    def test_nonfinite_epoch_is_invalid(self):
        for value in [float('nan'), float('inf'), float('-inf')]:
            self.assertEqual(normalize(value), (None, 'invalid'))

    def test_invalid_and_conflicting_zones_are_not_used_for_ordering(self):
        self.assertEqual(details('2026-11-02 10:00:00', explicit_timezone='Bad/Zone').status, 'invalid_timezone')
        conflict = details('2026-11-02T10:00:00Z', explicit_timezone='America/New_York')
        self.assertEqual((conflict.utc, conflict.status), (None, 'timezone_conflict'))
        self.assertEqual(details(1700000000, explicit_timezone='America/New_York').utc, normalize(1700000000)[0])

    def test_api_event_with_original_timestamp_is_still_utc_normalized(self):
        fail = Event('2026-11-02T10:00:00+05:30', 'pure', None, 'high', 'disk', 'disk 7 failed', 'x', 1, 'array-a', timestamp_original='original')
        clear = Event('2026-11-02T05:00:00Z', 'pure', None, 'high', 'disk', 'disk 7 failure cleared', 'x', 2, 'array-a', timestamp_original='original')
        finding = evaluate([clear, fail])[0]
        self.assertEqual(finding.state, 'RESOLVED')
        self.assertEqual(finding.duration_seconds, 1800)

    def test_future_replication_success_is_diagnosed_not_negative_lag(self):
        diagnostics = {}
        finding = self.scan([self.row(message='replication failed', last_successful_replication='2026-11-02T11:00:00Z')], diagnostics=diagnostics)[0]
        self.assertEqual(diagnostics['replication_success_after_event'], 1)
        self.assertIsNone(finding.replication_gap_seconds)
        self.assertIsNone(finding.max_replication_gap_seconds)

    def test_missing_event_clock_is_not_borrowed_from_replication_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.json'
            path.write_text(json.dumps({'message': 'replication failed', 'last_successful_replication': '2026-11-02T10:00:00Z'}))
            event = next(iter_file(path))
            self.assertIsNone(event.timestamp)
            self.assertEqual(event.timestamp_status, 'missing')
            self.assertEqual(event.context['last_successful_replication'], '2026-11-02T10:00:00.000000+00:00')

    def test_equal_time_failure_and_recovery_are_uncertain(self):
        diagnostics = {}
        finding = self.scan([self.row(), self.row(message='disk 7 failure cleared')], diagnostics=diagnostics)[0]
        self.assertEqual(finding.state, 'UNKNOWN')
        self.assertEqual(diagnostics['equal_timestamp_state_conflicts'], 1)

    def test_repeated_untimed_recoveries_cannot_erase_known_failure_clock(self):
        rows = [self.row(), self.row(None, 'disk 7 failure cleared'), self.row(None, 'disk 7 recovered')]
        finding = self.scan(rows)[0]
        self.assertEqual((finding.state, finding.severity), ('UNKNOWN', 'critical'))

    def test_replication_measurement_is_not_reused_as_fresh_lag(self):
        rows = [self.row(message='replication failed', replication_lag_seconds=120), self.row('2026-11-02T10:10:00Z', 'replication failed')]
        finding = self.scan(rows, rpo_target_seconds=60)[0]
        self.assertIsNone(finding.replication_gap_seconds)
        self.assertEqual(finding.max_replication_gap_seconds, 120)
        self.assertEqual(finding.severity, 'critical')

    def test_strict_validation_rejects_missing_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.json'
            row = self.row()
            row.pop('timestamp')
            path.write_text(json.dumps(row))
            args = build_parser().parse_args(['validate', str(path), '--strict'])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(args.func(args), 2)

    def test_strict_validation_includes_invalid_replication_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.json'
            path.write_text(json.dumps(self.row(message='replication failed', last_successful_replication='2026-02-30T10:00:00Z')))
            args = build_parser().parse_args(['validate', str(path), '--strict'])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(args.func(args), 2)

    def test_protected_drive_rebuild_has_lower_contextual_severity(self):
        rows = [self.row(redundancy='healthy', service_impact=False), self.row('2026-11-02T10:01:00Z', 'disk 7 rebuilding')]
        finding = self.scan(rows)[0]
        self.assertEqual((finding.state, finding.severity, finding.severity_basis), ('RECOVERING', 'medium', 'protected_drive_recovering'))

    def test_simultaneous_controller_and_path_escalate_on_same_device(self):
        rows = [self.row(message='controller A failed'), self.row('2026-11-02T10:00:15Z', 'path 1 failed')]
        self.assertEqual({(f.rule_id, f.severity, f.severity_basis) for f in self.scan(rows)}, {('STO-002', 'critical', 'controller_path_correlation'), ('STO-004', 'critical', 'controller_path_correlation')})

    def test_controller_path_different_devices_or_distant_times_do_not_correlate(self):
        for row in [self.row('2026-11-02T10:00:15Z', 'path 1 failed', host='array-b'), self.row('2026-11-02T11:00:00Z', 'path 1 failed')]:
            self.assertTrue(all(f.severity == 'high' for f in self.scan([self.row(message='controller A failed'), row])))

    def test_missing_identity_or_clock_cannot_claim_simultaneous_failure(self):
        for rows in [
            [{'timestamp': '2026-11-02T10:00:00Z', 'message': 'controller A failed'}, {'timestamp': '2026-11-02T10:00:15Z', 'message': 'path 1 failed'}],
            [self.row(None, 'controller A failed'), self.row(None, 'path 1 failed')],
        ]:
            self.assertTrue(all(f.severity == 'high' for f in self.scan(rows)))

    def test_cleared_path_does_not_escalate_active_controller(self):
        rows = [self.row(message='controller A failed'), self.row('2026-11-02T10:00:15Z', 'path 1 failed'), self.row('2026-11-02T10:00:30Z', 'path 1 failure cleared')]
        self.assertTrue(all(f.severity == 'high' for f in self.scan(rows)))

    def test_correlation_window_can_be_tightened_and_is_bounded(self):
        rows = [self.row(message='controller A failed'), self.row('2026-11-02T10:00:15Z', 'path 1 failed')]
        self.assertTrue(all(f.severity == 'high' for f in self.scan(rows, correlation_window_seconds=10)))
        for value in [0, -1, 86401, float('nan'), True, 'oops']:
            with self.assertRaises(ValueError):
                self.scan(rows, correlation_window_seconds=value)

    def test_correlation_handles_datetime_boundaries(self):
        for time in ['0001-01-01T00:00:00Z', '9999-12-31T23:59:59Z']:
            findings = self.scan([self.row(time, 'controller A failed'), self.row(time, 'path 1 failed')])
            self.assertTrue(all(f.severity == 'critical' for f in findings))

    def test_active_dr_outage_is_distinct_from_generic_replication_failure(self):
        generic = self.scan([self.row(message='replication failed')])[0]
        dr = self.scan([self.row(message='replication failed', dr_target=True, service_impact=False)])[0]
        self.assertEqual(generic.severity, 'high')
        self.assertEqual((dr.severity, dr.severity_basis), ('critical', 'disaster_recovery_target_outage'))

    def test_uncertain_recovery_does_not_lower_dr_criticality(self):
        rows = [self.row(message='replication failed', dr_target=True), self.row(None, 'replication resync completed')]
        finding = self.scan(rows)[0]
        self.assertEqual((finding.state, finding.severity), ('UNKNOWN', 'critical'))

    def test_optional_index_uses_only_complete_explicit_components(self):
        values = dict(impact=80, urgency=60, correlation=40, duration=20, exposure=100)
        self.assertEqual(score(values), 60)
        finding = self.scan([self.row(risk_components=values)])[0]
        self.assertEqual(finding.business_risk_score, 60)
        self.assertEqual(finding.severity, 'critical')
        self.assertIsNone(self.scan([self.row()])[0].business_risk_score)
        text = render(AnalysisReport([], 1, {}, {}, [finding]), 'text')
        self.assertIn('Uncalibrated index, not a probability', text)

    def test_invalid_or_partial_components_are_rejected_without_echoing_values(self):
        for values in [{'impact': 100}, dict(impact=True, urgency=0, correlation=0, duration=0, exposure=0), dict(impact=10**1000, urgency=0, correlation=0, duration=0, exposure=0), dict(impact=float('nan'), urgency=0, correlation=0, duration=0, exposure=0)]:
            with self.assertRaises(ValueError):
                components(values)

    def test_business_context_and_clock_metadata_do_not_cross_ai_boundary(self):
        values = dict(impact=80, urgency=60, correlation=40, duration=20, exposure=100)
        finding = self.scan([self.row(message='replication failed', dr_target=True, risk_components=values)])[0]
        payload = json.dumps(build_ai_request(AnalysisReport([], 1, {}, {}, [finding])))
        self.assertIn('disaster_recovery_target_outage', payload)
        self.assertNotIn('risk_components', payload)
        self.assertNotIn('array-a', payload)
        self.assertNotIn('timezone_original', payload)
