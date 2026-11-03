# P1 review remediation — v0.4.0

This release addresses the P1 correctness/reliability findings in the supplied v0.2.0 review, building on the [P0 fixes](P0_REVIEW.md). Verification uses synthetic data and mocked API transport. It is not a production certification or a measured detection-accuracy benchmark.

## Reproduced baseline and result

| Check | v0.3.0 baseline | v0.4.0 result |
|---|---|---|
| Malformed JSONL containing recognized vendor/severity, `validate --strict` | Exit 0 | Exit 1 with file and physical line; optional private quarantine |
| Recovery file visited before an older failure file | OPEN | RESOLVED after disk-backed chronological ordering |
| Protected drive with explicit healthy redundancy and no service impact | Critical default | High with `confirmed_healthy_redundancy` basis |
| Generic event from a previously identified host | Vendor unknown | Consistent same-device attribution; conflicts stay unknown |
| AI request contract | Free text, no output budget | Strict schema, 4096-token default and local reference/action validation |
| AI timeout | Exit 1 and no report file | Exit 1, local report retained with `ai_status=failed` |

## P1 changes

### Recovery, duplicates and identity

Events with usable clocks are ordered across files using temporary SQLite storage. Exact repeated records are counted separately from unique active-state events; all raw input events remain in `event_count`. A repeated record does not create another device/resource identity or reset a resolved incident. A new failure after recovery reopens it and starts a new duration cycle. An untimed identical message after recovery conservatively reopens because it cannot be distinguished from a new failure; it is not claimed to be proven replay.

Original timestamps, UTC values and normalization status remain available in events and bounded local evidence. A known timed failure cannot be cleared by an unsequenced recovery. Missing, invalid, ambiguous and assumed clocks are visible in diagnostics rather than silently treated as trustworthy.

Vendor precedence is forced override, explicit structured metadata, operator inventory, message hints, then consistent history for the same device. Contradictory history is never propagated as a guess, and no unrelated device supplies a fallback vendor. The inventory is bounded, local, operator-supplied configuration; it does not authenticate a device.

### Strict JSON Lines

`--strict-format` rejects malformed and non-object JSONL with the source line. `validate --strict` implies this parsing mode. Lenient mode remains available but counts malformed/non-object records. Optional quarantine writes original rejected records to a private file outside the scanned directory, including the first rejection in strict mode. Treat it as sensitive raw data.

### UTC clocks and ordering

ISO timestamps with offsets normalize to UTC. Unix epoch seconds/milliseconds are supported. Naive timestamps use the explicit `--assume-timezone` policy (default UTC) and record that assumption. Yearless RFC3164 syslog requires `--assume-year`. Impossible dates, date-only values and ambiguous/nonexistent DST wall-clock values are not guessed.

Usable clocks are ordered globally; equal clocks use input order. Unusable clocks retain input order after timed events and cannot silently close timed failures. This is an explicit uncertainty policy, not recovery of missing temporal information. `tzdata` supplies portable IANA data.

### Contextual severity and replication

The report includes `severity_basis`. Policies depend on explicit context rather than unvalidated weighted scores:

- A protected drive is reduced only when healthy redundancy and no service impact are both supplied.
- Multiple active drives are correlated only within the same explicitly identified protection group and device.
- Confirmed storage service impact or redundancy loss can escalate severity.
- Replication lag is derived only from an explicit lag measurement or a usable last-success timestamp. An operator-specified RPO target can escalate lag violations.
- Successful resync resets current lag and retains maximum *observed* lag and current-cycle duration. Unknown lag remains null; outage duration is not substituted for lag or actual data loss.

These policies are explainable heuristics, not calibrated business-risk scores. Context fields and log-state interpretations still require operator/vendor validation.

### Structured and bounded AI

The request uses strict JSON Schema and a 4096-token default (`STORAGE_LOG_AI_MAX_OUTPUT_TOKENS`, 256–8192). Output is restricted to up to eight supplied finding-group references, observation codes and approved verification actions. Local validation checks cross-field reference ownership, state consistency, duplicate references, allowed actions, mandatory uncertainty, operator approval and uncalibrated confidence. Incomplete, malformed, unsupported or oversized responses are rejected.

The model cannot add arbitrary free-form root causes or confidence percentages to the rendered assessment. UNKNOWN state cannot be asserted active; resolved history cannot receive active repair actions. References identify local aggregate findings, not raw-line citations or proof of causality. Raw messages, paths, device names and log-injected instructions remain excluded from the provider request. This intentionally limits AI to prioritization of local facts and approved checks.

Local findings are preserved for API errors, missing credentials/dependencies, invalid structured output or token exhaustion. Output files are checkpointed before the request. The final report records AI status/error and returns exit 1 if AI did not complete; raw provider error text is not echoed.

## Verification

```bash
python -m pip install -e '.[ai,dev]'
python -W error::ResourceWarning -m unittest discover -s tests -v
ruff check --config pyproject.toml .
python scripts/benchmark_p0.py
python scripts/benchmark_p0.py --format json
```

The expanded suite covers cross-file recovery, stale/unknown clocks, offsets and DST, duplicate records and reopening, vendor inventory/conflicts, strict parsing/quarantine, severity policy, replication resync, malicious/unsupported AI output, token budgets and preservation of local reports. Existing P0/privacy and mocked SDK transport tests remain active. No real API requests, charges or customer logs were involved.

### Local million-event measurements

Each size runs in a fresh process, with one distinct device incident per synthetic event. Exact event and incident counts are checked. The acceptance limits are peak RSS below 128 MiB and less than 32 MiB growth for 10x events.

| Format | Events / distinct incidents | Peak RSS (MiB) | Analysis time (seconds) |
|---|---:|---:|---:|
| Text log | 100,000 | 41.23 | 6.58 |
| Text log | 1,000,000 | 34.86 | 72.14 |
| JSON array | 100,000 | 42.25 | 5.05 |
| JSON array | 1,000,000 | 39.48 | 56.82 |

Measured locally on macOS/Python 3.14, excluding input generation. Small subsequent guard/policy changes are covered by the regression suite; CI reruns the benchmarks on the published code. Figures depend on platform, workload and storage. Temporary disk use grows with stored events and unique incidents; bounded working memory does not imply bounded disk space.

## Limits retained

The tool remains alpha. Generic event-state rules and operator-supplied context are not vendor-certified interpretations. It does not add product-specific adapters, topology discovery, continuous collection, a measured detection-accuracy guarantee, or automatic remediation. Reports retain bounded evidence samples, and AI references are aggregate-level. Richer provenance/export and benchmark calibration remain subsequent work.

Scratch databases are private but unencrypted and cleaned on normal completion/handled errors. Abrupt termination may leave scratch directories. Timestamp assumptions and unknown identities remain visible; missing information is not invented.
