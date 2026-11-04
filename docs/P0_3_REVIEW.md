# P0-3: bounded-memory processing of large logs

The earlier v0.3/v0.4 changes replaced whole-file event lists with lazy ingestion,
streaming JSON parsing, SQLite event ordering and incident state, exact aggregate
counts, and at most five evidence/device samples per finding group. This follow-up
addresses remaining parser and chronology risks and expands the acceptance test.

- The chronology index now includes the same `stamp IS NULL` expression as the
  playback query. SQLite can read events in order from the index without building
  another sort of all serialized event payloads. A query-plan regression test
  checks the index is used and no temporary sorting B-tree appears.
- JSON numeric tokens are limited to 128 characters before the incremental parser
  receives them, including tokens split across read buffers and ignored envelope
  metadata. Existing string, record and nesting limits remain in place. Strict
  JSONL rejects overlong tokens; permissive JSONL retains its documented malformed
  record fallback and diagnostic behavior.
- Each event's clauses are split once, avoiding repeated list construction for
  every clause/rule match.
- The benchmark now supports text, JSON arrays, JSONL and CSV, with timestamps out
  of input order and one distinct device incident per event. CI covers all four.
  Each format runs 100,000 and 1,000,000 events in fresh worker processes, checks
  exact event and incident counts, and enforces peak RSS below 128 MiB and growth
  below 32 MiB for the tenfold increase.

The chronology pass stages events on disk before applying state transitions in
UTC order; it does not retain those events in a Python list. Working memory is
bounded, while temporary disk use grows with input and incident cardinality.
Temporary databases are removed on normal completion and handled failures.
Reports contain bounded samples, not exhaustive incident history. The existing
10,000-file, 1 MiB record and 64-level nesting limits still apply.

Reproduce with:

```sh
python -W error::ResourceWarning -m unittest discover -s tests -v
ruff check .
python scripts/benchmark_p0.py --format log
python scripts/benchmark_p0.py --format json
python scripts/benchmark_p0.py --format jsonl
python scripts/benchmark_p0.py --format csv
```

Local validation on macOS/Python 3.14: all 82 unit tests pass with resource warnings
promoted to errors; Ruff and whitespace checks pass. The four benchmarks ran
concurrently, so elapsed times reflect contention and are not throughput claims.

| Format | Events / distinct incidents | Peak RSS (MiB) | Seconds |
|---|---:|---:|---:|
| Text | 100,000 | 40.84 | 7.05 |
| Text | 1,000,000 | 34.69 | 123.05 |
| JSON array | 100,000 | 41.98 | 5.60 |
| JSON array | 1,000,000 | 39.45 | 104.40 |
| JSONL | 100,000 | 37.36 | 6.00 |
| JSONL | 1,000,000 | 34.69 | 102.69 |
| CSV | 100,000 | 40.84 | 5.30 |
| CSV | 1,000,000 | 34.78 | 95.09 |
