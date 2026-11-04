# P1-6 and P1-7 follow-up evidence

Scope: the corresponding sections of the shared review, on top of main commit `f80178b`. Earlier P0/P1 fixes remain enabled. All examples and tests are synthetic; no provider calls or customer logs are used.

## Reproduced failures and fixes

| Baseline case | Previous behavior | Current-source behavior |
|---|---|---|
| `2026-11-02 10:00:00 +05:30` in text | Offset dropped; 10:00 UTC assumed | Original offset retained; 04:30 UTC |
| Structured naive clock with `timezone=America/New_York` | Metadata ignored; UTC fallback | 15:00 UTC; original zone identified |
| Basic date `20261102` | Midnight silently invented | Missing-time diagnostic, no event clock |
| Timed failure followed by repeated distinct untimed recoveries | Later recovery could clear the clock anchor | UNKNOWN; known chronology anchor retained |
| Last replication success later than event | Unknown gap without causal diagnostic | Explicit chronology diagnostic; no negative inferred gap |
| Simultaneous controller/path failure | Two high defaults | Critical when explicit device, known active cycle starts, and window agree |
| Declared DR-target outage | Generic high replication default | Critical with fixed DR-outage basis |
| Protected rebuilding drive | Same high/default policy | Medium only with healthy redundancy and explicit no service impact |

## Time model and diagnostics

UTC strings use canonical microsecond precision. Original timestamp text, original timezone metadata/offset, timezone fallback, and year assumption remain in Event fields and bounded local evidence. Naive clocks use the declared CLI policy. Explicit timezone conflicts, impossible dates, date-only clocks, non-finite epochs and DST ambiguity are not silently sequenced. Negative epoch milliseconds are handled consistently with seconds.

Chronology ordering remains disk-backed and bounded in working memory. The analyzer counts per-device out-of-input-order events, replication-success-after-event conflicts, and equal-time conflicting failure/recovery states. Missing clocks cannot establish elapsed time or simultaneity. Strict validation reports missing or unusable event/replication clocks; it is not a full timeline analysis.

## Severity and optional index

The deterministic severity policies distinguish protected single-drive failure/recovery, multiple active drives in one supplied group/device, simultaneous active controller/path failures, and active DR-target outages. Controller/path correlation defaults to 300 seconds, is configurable up to 86,400 seconds, and requires explicit device identity and known current-cycle starts. Different devices, source-only identities, missing clocks, distant starts, and cleared states cannot produce that escalation. The window is an operator policy, not a calibrated causal model.

The optional advisory index implements the review's proposed `0.30I + 0.25U + 0.20C + 0.15D + 0.10E` only when all five normalized inputs are explicitly supplied. Values are bounded/finite, booleans are rejected, and absent/partial inputs are not inferred. It does not set or reduce the report's operational severity. Grouped findings retain the maximum supplied index and its components. It is explicitly uncalibrated, not a probability or production validation. Raw components and clock/device metadata remain outside the AI boundary.

## Verification

```bash
python -m pip install -e '.[ai,dev]'
python -W error::ResourceWarning -m unittest discover -s tests -v
ruff check --config pyproject.toml .
python scripts/benchmark_p0.py
python scripts/benchmark_p0.py --format json
python -m build
```

The suite now has 105 tests, including 28 follow-up regressions. It covers offset extraction, IANA provenance, assumed year/timezone, date-only and non-finite clocks, repeated unsequenced recoveries, impossible replication chronology, stale lag, timestamp ties, strict validation, contextual recovery, false-correlation guards, datetime boundaries, explicit DR role, normalized index validation, and the unchanged private AI boundary.

Local million-event text benchmark: 100,000 events/distinct incidents at 40.80 MiB peak RSS and 7.88 s; 1,000,000 at 34.75 MiB and 85.60 s. Exact counts, peak below 128 MiB, and less than 32 MiB growth for 10x inputs pass. These initial measurements preceded small additional chronology/type guards; the regression suite covers those guards and CI reruns the final source. The JSON benchmark also passes: 100,000 events/distinct incidents at 41.95 MiB and 6.32 s; 1,000,000 at 39.19 MiB and 68.84 s. Source distribution and wheel builds, lint, and all 105 tests pass locally.

## Limits

Clock assumptions and source-supplied context are not authenticated evidence. Cross-device clock skew is not repaired, causal ordering of equal/unknown clocks is not invented, and actual data loss is not derived from outage duration. Scratch space remains private but unencrypted and grows with records/identities. No topology discovery, vendor certification, calibrated risk/accuracy benchmark, new public release, or automatic remediation is added.
