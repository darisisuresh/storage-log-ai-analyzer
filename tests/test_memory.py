import io
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path

from storage_log_analyzer.ingest import MAX_JSON_NUMBER, _JSONReader, iter_file
from storage_log_analyzer.models import Event
from storage_log_analyzer.rules import _ordered_events, evaluate


class MemoryTests(unittest.TestCase):
    def test_chronology_uses_index_without_temporary_sort(self):
        with closing(sqlite3.connect(':memory:')) as db:
            events = (
                Event(stamp, 'pure', None, 'high', 'drive', 'disk 7 failed', 'test', i, device=f'array-{i}')
                for i, stamp in enumerate(['2026-11-03T10:00:00Z', None, '2026-11-02T10:00:00Z'])
            )
            ordered = list(_ordered_events(db, events, {}))
            self.assertEqual([e.line for e in ordered], [2, 0, 1])
            plan = db.execute('EXPLAIN QUERY PLAN SELECT payload FROM ordered_events ORDER BY stamp IS NULL, stamp, seq').fetchall()
            details = ' '.join(str(row) for row in plan)
            self.assertIn('event_time_order', details)
            self.assertNotIn('TEMP B-TREE', details)

    def test_numeric_token_limit_across_reader_chunks(self):
        reader = _JSONReader(io.BytesIO(b'[' + b'1' * (MAX_JSON_NUMBER + 1) + b']'))
        with self.assertRaisesRegex(ValueError, 'JSON number'):
            while reader.read(7):
                pass

    def test_large_number_in_ignored_envelope_metadata_is_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            for suffix, content in [
                ('.json', '{"events":[],"metadata":' + '1' * 100000 + '}'),
                ('.jsonl', '{"message":"disk 7 failed","number":' + '1' * 100000 + '}'),
            ]:
                path = Path(folder) / ('events' + suffix)
                path.write_text(content)
                with self.assertRaises(ValueError):
                    list(iter_file(path, strict_format=True))

    def test_numbers_inside_strings_are_not_numeric_tokens(self):
        data = b'{"message":"' + b'1' * 1000 + b'","value":1.25e-12}'
        reader = _JSONReader(io.BytesIO(data))
        self.assertEqual(reader.read(), data)

    def test_high_cardinality_counts_and_samples_stay_bounded(self):
        consumed = 0

        def events():
            nonlocal consumed
            for i in range(2000):
                consumed += 1
                yield Event(None, 'pure', None, 'high', 'drive', 'disk 7 failed', 'test', i, device=f'array-{i}')

        findings = evaluate(events())
        self.assertEqual(consumed, 2000)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].count, 2000)
        self.assertEqual(findings[0].incident_count, 2000)
        self.assertLessEqual(len(findings[0].evidence), 5)
        self.assertLessEqual(len(findings[0].devices), 5)
