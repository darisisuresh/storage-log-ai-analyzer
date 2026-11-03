# P0 review remediation — v0.3.0

Reviewed against the user-supplied ChatGPT review of v0.2.0. This document records synthetic local tests; it does not certify production reliability or detection accuracy.

## Confirmed baseline

- The review's failure / failure-cleared / no-active-failures example produced three STO-001 matches in v0.2.0.
- Local redaction left the tested IPv6, labeled host/user/tenant, password and bearer-token values visible.
- Materializing 100,000 benign events used 28,204,689 bytes of traced Python memory. This allocation metric is different from the process RSS metric below and should not be compared as a direct ratio.

## Implemented P0 changes

1. Incremental incident states are keyed by rule, device/source and resource in temporary SQLite storage. Negative and recovery-only events do not create active failures. Matching recovery retains occurrence history but changes current state to RESOLVED. Different-device and different-resource recoveries cannot clear each other. UTC timestamp comparisons reject known older recovery updates; naive/missing timestamps use input order.
2. The AI request builder copies only allowlisted categorical counts and fixed local rule metadata. It does not copy raw evidence, log messages, paths, devices, arbitrary titles, or arbitrary dictionary keys. A no-network request preview uses the same builder as the provider call. Local redaction was expanded separately, with atomic streaming output.
3. Ingestion, counters and rule evaluation consume events incrementally. JSON uses ijson. SQLite's cache is capped at 4 MiB, output groups and evidence samples are bounded, and high-cardinality identities live on disk rather than in a Python dictionary.

## Acceptance tests

`tests/test_p0.py` covers negative/recovery examples across rule families, reopening, separate resources and devices, mixed-host vendor attribution, stale UTC recovery, acknowledgements/recovery-in-progress, secret-bearing payloads, structural request budgeting, provider-free preview, CSV/JSON/JSONL identity, oversized records, compatibility-helper limits and atomic redaction failure. Existing mocked SDK transport tests also pass.

```bash
python -m pip install -e '.[ai,dev]'
python -W error::ResourceWarning -m unittest discover -s tests -v
ruff check --config pyproject.toml .
python scripts/benchmark_p0.py
python scripts/benchmark_p0.py --format json
```

Benchmark script requires a POSIX platform (macOS/Linux). Each size runs in a fresh subprocess, with one synthetic input file and a distinct device identity for every failure. The script verifies exact event/incident counts, peak process RSS below 128 MiB, and growth below 32 MiB for 10x events. Disk-backed incident state grows with distinct identities and is removed after each run.

| Format | Events / distinct incidents | Peak RSS (MiB) | Analysis time (seconds) |
|---|---:|---:|---:|
| Text log | 100,000 | 33.28 | 3.78 |
| Text log | 1,000,000 | 32.92 | 38.86 |
| JSON array | 100,000 | 34.88 | 2.71 |
| JSON array | 1,000,000 | 34.03 | 26.30 |

Measured locally on macOS with Python 3.14. Input generation is excluded from analysis time. Values depend on platform, workload and storage; these are not throughput guarantees. Small subsequent guard changes preserve the same bounded design and are covered by the regression suite. GitHub CI reruns the benchmarks on the published code.

## Explicit limits

- Maximum 10,000 files per scan.
- Text/CSV record budget: 1,048,576 characters. JSON string-token and decoded-record budget: 1 MiB; nesting limit: 64. Oversized or overly nested input fails explicitly.
- Device/resource identity fields: 256 characters; timestamp fields: 128.
- Small-input `parse_file` compatibility helper: 10,000 events or an 8 MiB text budget. `iter_file` and lazy `ingest` are the streaming APIs.
- Reports aggregate by rule/state, retaining exact counts and at most five evidence/device samples per group. This is not an exhaustive incident-history export.
- A private temporary SQLite database stores local identity/evidence data. It is cleaned up on success/error, is not encrypted, and requires sufficient temporary disk space.

## Remaining work outside P0

Recovery/negation rules are deliberately conservative heuristics, not general language understanding or vendor-certified state interpretation. Without identity, correlation falls back to source-file scope. Globally sorting all files, ambiguous recovery-only histories, strict malformed-JSONL validation, topology inventory, contextual severity, and full structured AI evidence attribution remain P1 work. Unknown vendor lines are retained as unknown instead of inheriting another device's vendor.

No blanket sanitization guarantee is made for local reports or arbitrary free-form text. The stronger AI boundary is enforced by excluding raw text/identities, rather than relying on regex redaction.
