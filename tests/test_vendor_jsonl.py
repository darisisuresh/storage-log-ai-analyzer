import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from storage_log_analyzer.cli import build_parser
from storage_log_analyzer.ingest import ingest, iter_file
from storage_log_analyzer.rules import evaluate
from storage_log_analyzer.vendors import detect_vendor


class VendorJSONLTests(unittest.TestCase):
    def run_command(self, *argv):
        args = build_parser().parse_args(argv)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = args.func(args)
        return code, out.getvalue(), err.getvalue()

    def test_later_conflict_does_not_label_generic_lines_in_any_command(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.jsonl'
            source.write_text('\n'.join(json.dumps({'host': 'array-a', 'message': message}) for message in (
                'Pure Storage disk 7 failed', 'disk 7 failed', 'HPE disk 7 failed', 'disk 7 failed',
            )))
            for command in ('analyze', 'summary'):
                argv = [command, str(source), '--format', 'json']
                if command == 'analyze':
                    argv += ['--fail-on', 'never']
                code, out, _ = self.run_command(*argv)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out)['vendors'], {'pure': 1, 'unknown': 2, 'hpe': 1})
            code, out, _ = self.run_command('validate', str(source))
            self.assertEqual(code, 0)
            self.assertIn('Unknown vendor: 2', out)

    def test_late_hint_is_shared_only_with_the_same_host(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.log'
            source.write_text('2026-11-02T10:00:00Z host-a disk 7 failed\n'
                              '2026-11-02T10:00:01Z host-b disk 7 failed\n'
                              '2026-11-02T10:00:02Z HOST-A Dell EMC disk 7 failed\n')
            _, events = ingest(source)
            self.assertEqual([e.vendor for e in events], ['emc', 'unknown', 'emc'])

    def test_ambiguous_vendor_message_remains_unknown_even_with_host_history(self):
        self.assertEqual(detect_vendor('Pure Storage communicating with HPE'), 'unknown')
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.log'
            source.write_text('host=a Pure Storage disk failed\nhost=a Pure Storage HPE disk failed\n')
            _, events = ingest(source)
            seen = []
            evaluate(events, on_event=lambda e: seen.append((e.vendor, e.vendor_source)))
            self.assertEqual(seen, [('pure', 'message'), ('unknown', 'ambiguous_message')])

    def test_case_insensitive_inventory_and_conflicting_alias_rejection(self):
        with tempfile.TemporaryDirectory() as folder:
            source, inventory = Path(folder) / 'input.log', Path(folder) / 'inventory.json'
            source.write_text('host=ARRAY-A disk failed\n')
            inventory.write_text(json.dumps({'devices': {'Array-A': {'vendor': 'hpe'}}}))
            _, events = ingest(source, inventory=inventory)
            self.assertEqual(next(events).vendor, 'hpe')
            events.close()
            inventory.write_text(json.dumps({'devices': {'Array-A': {'vendor': 'hpe'}, 'array-a': {'vendor': 'pure'}}}))
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                ingest(source, inventory=inventory)

    def test_cross_file_conflict_stays_unknown_after_repeated_hints(self):
        with tempfile.TemporaryDirectory() as folder:
            for name, message in [('a', 'Pure Storage'), ('b', 'HPE'), ('c', 'Pure Storage'), ('d', '')]:
                (Path(folder) / (name + '.log')).write_text(f'host=array-a {message} disk failed\n')
            _, events = ingest(Path(folder))
            rows = list(events)
            self.assertEqual([e.vendor for e in rows], ['pure', 'hpe', 'pure', 'unknown'])
            self.assertEqual(rows[-1].vendor_source, 'conflicting_device_history')

    def test_unidentified_event_never_inherits_file_vendor(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.log'
            source.write_text('Pure Storage disk failed\ndisk failed\n')
            _, events = ingest(source)
            self.assertEqual([e.vendor for e in events], ['pure', 'unknown'])

    def test_all_commands_reject_malformed_jsonl_in_strict_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.jsonl'
            source.write_text('\n{bad\n')
            for command in ('analyze', 'summary', 'validate'):
                code, _, err = self.run_command(command, str(source), '--strict-format')
                self.assertEqual(code, 1)
                self.assertIn(str(source) + ':2: malformed_jsonl', err)

    def test_strict_jsonl_rejects_duplicates_and_numeric_overflow_with_physical_line(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.jsonl'
            for line in ('{"host":"a","host":"b"}', '{"metadata":{"x":1,"x":2}}', '{"lag":1e999}', '{"lag":-1e999}'):
                source.write_text('\n{"message":"ok"}\n' + line + '\n')
                with self.assertRaisesRegex(ValueError, ':3: malformed_jsonl'):
                    list(iter_file(source, strict_format=True))

    def test_lenient_mode_warns_counts_and_quarantines_without_echoing_raw_text(self):
        with tempfile.TemporaryDirectory() as folder:
            source, quarantine = Path(folder) / 'input.jsonl', Path(folder) / 'rejected.jsonl'
            source.write_text('{bad secret-token\n42\n{"message":"ok"}\n')
            for command in ('analyze', 'summary', 'validate'):
                argv = [command, str(source), '--quarantine', str(quarantine)]
                if command != 'validate':
                    argv += ['--format', 'json']
                if command == 'analyze':
                    argv += ['--fail-on', 'never']
                code, out, err = self.run_command(*argv)
                self.assertEqual(code, 0)
                self.assertIn('2 invalid JSONL record(s)', err)
                self.assertNotIn('secret-token', err)
                rejected = [json.loads(line) for line in quarantine.read_text().splitlines()]
                self.assertEqual([r['line'] for r in rejected], [1, 2])
                if command != 'validate':
                    diagnostics = json.loads(out)['diagnostics']
                    self.assertEqual(diagnostics['malformed_jsonl'], 1)
                    self.assertEqual(diagnostics['non_object_jsonl'], 1)

    def test_strict_mode_never_calls_ai_or_overwrites_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / 'input.jsonl', Path(folder) / 'report.json'
            source.write_text('{bad\n')
            output.write_text('existing report')
            from unittest.mock import patch
            with patch('storage_log_analyzer.cli.assess', side_effect=AssertionError('AI called')):
                code, _, err = self.run_command('analyze', str(source), '--strict-format', '--ai', '-o', str(output))
            self.assertEqual(code, 1)
            self.assertIn(':1: malformed_jsonl', err)
            self.assertEqual(output.read_text(), 'existing report')
