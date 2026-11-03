# Changelog

## v0.4.0 — P1 reliability and auditable AI

### Input, identity, and time

- Added `--strict-format`: malformed/non-object JSON Lines records fail with a source path and physical line number. `validate --strict` also enables it. Lenient mode counts rejections in diagnostics.
- Added optional `--quarantine PATH` for private, local rejected records outside the input directory. Quarantine is raw sensitive data, not AI-bound data.
- Added `--inventory PATH` for per-device vendor mapping. Explicit vendor override and structured metadata take precedence; consistent same-device history can fill unknowns, while conflicting hints remain unknown.
- UTC timestamps preserve their original text and normalization status. Naive values use the explicit `--assume-timezone` policy (default UTC); yearless syslog requires `--assume-year`. Invalid, missing-time, and ambiguous DST values are not guessed.
- Events are ordered across files in a temporary disk-backed database before incident transitions. Unsequenced recovery cannot silently clear a timed failure.

### Incident correctness and severity

- Exact repeated records retain total active-state event counts, unique counts, repeated-record counts, and one device/resource identity. A new failure after recovery reopens the incident.
- Severity records its deterministic basis. Confirmed healthy redundancy with no service impact permits a lower protected-drive severity; confirmed storage service impact, redundancy loss, multiple active drives in one explicit protection group, or replication lag exceeding an explicit target can escalate it.
- Added `--rpo-target-seconds`. Replication lag uses an explicit measurement or a known last-success timestamp. Successful resync resets current lag while retaining the maximum observed lag and current-cycle outage duration. These fields do not measure data loss.

### Auditable optional AI

- Added strict structured output, an explicit token budget (4096 by default; configurable from 256 to 8192), and local validation of every finding/evidence reference, observation, action, and uncertainty field.
- AI can prioritize up to eight local finding groups and choose approved verification actions. Arbitrary free-form root causes, unsupported claims, fabricated confidence scores and unknown references are rejected.
- References point to local aggregate findings; raw log messages, identities and paths still do not cross the AI boundary.
- API failure, invalid output, refusal or token exhaustion preserves local findings in the report with `ai_status=failed`, a safe error, and exit code 1. Output files are checkpointed before the AI request.

### Verification and compatibility

- Added the required `tzdata>=2026.6` package for portable IANA timezone support. `ijson` remains required and the AI SDK remains optional.
- Added P1 regression and mocked SDK tests. See [P1 review evidence](https://github.com/darisisuresh/storage-log-ai-analyzer/blob/main/docs/P1_REVIEW.md) for reproduced failures, benchmark results and limits.
- This remains an alpha prerelease. Contextual severity policies are explicit rules, not calibrated business-risk scores or vendor-certified incident interpretations.


## v0.3.0 — P0 correctness, privacy, and memory fixes

### P0-1: distinguish failures from negative/recovery messages

- Added OPEN, ACKNOWLEDGED, RECOVERING and RESOLVED incident transitions, keyed by rule, device/source, and resource.
- Historical occurrences are retained. Resolved incidents are excluded from current risk and the CLI failure threshold.
- Recovery for another device or an unspecified resource cannot clear an identified disk incident. Known older UTC recovery events cannot overwrite a newer active failure.
- Negative status phrases no longer create active incidents in the regression examples. The outage phrase `no active paths` remains active.
- Mixed-device files no longer inherit a file-wide vendor guess; unidentified vendors remain unknown.

### P0-2: restrict the AI boundary

- Raw evidence, messages, paths, device names, arbitrary map keys and log-provided titles are excluded from AI requests by construction.
- Requests contain only fixed rule metadata, allowlisted vendor/severity counts, state, and finding references. JSON is built structurally; it is not cut mid-record.
- Added `analyze PATH --ai-preview -o request.json` to save the exact request body without a key or API call. `--ai` and `--ai-preview` are mutually exclusive.
- Expanded local redaction of known credentials, IPv6, labeled identities, hosts and paths. This helper remains heuristic and requires manual review; its guarantees are separate from the AI schema boundary.

### P0-3: stream input and bound working memory

- Text, CSV, JSON Lines and JSON records stream into incremental counters and rule evaluation.
- Added `ijson>=3.6.0,<4` as a required dependency for incremental JSON parsing; SQLite uses the Python standard library.
- Per-device state is held in a temporary SQLite database with a 4 MiB cache, bounded output samples, and cleanup on completion or failure. Temporary disk usage grows with distinct incident identities.
- Added explicit record/nesting/identity and file-count limits, and atomic streaming redaction output.
- `parse_file` remains a small-input compatibility helper, capped at 10,000 events and an 8 MiB text budget. Integrations should use `iter_file` or the lazy `ingest` event iterator.

### Verification and limits

See [P0 review evidence](docs/P0_REVIEW.md) for reproduction commands, memory measurements and remaining limitations. Automated tests use synthetic data and mocked API transport; no customer logs or real API calls were used. This is an alpha prerelease, not a production certification.


## v0.2.0 — Dependency refresh and reliability fixes

### Updated packages

- Optional AI SDK: `openai>=3.42.1,<4` (previously `>=1.40,<3`).
- Build backend: `setuptools>=84.2.1,<85`; modern SPDX license metadata.
- Development tools: `ruff==0.17.3` and `build==1.6.1`.
- Base analysis still has no third-party runtime dependencies. Python 3.10+ remains supported.

### Fixes and additions

- Added a user guide and downloadable PDF, linked from the README and Updates section.

- Added `storage-log-analyzer --version`.
- Explicit `--vendor` now takes precedence over detected vendor text.
- JSON scalars and malformed `events` envelopes produce actionable input errors.
- Non-object JSON Lines records no longer cause attribute errors.
- Empty analysis inputs fail instead of displaying a reassuring report without events.
- File permission and output-write failures produce concise CLI errors.
- Optional AI uses a bounded timeout, managed client cleanup, `store=False`, and sanitized SDK error messages. An empty AI response is reported as an error. `store=False` disables response storage; it does not promise zero provider retention.
- Source distributions now include guides, sample logs, and release documentation.
- Added regression tests and SDK transport tests without real API requests or API keys.
- CI covers Python 3.10, 3.12, and 3.14, with and without AI extras, plus lint and package builds.

### Upgrade

```bash
git pull
python -m pip install --upgrade -e .
# Optional AI and development tooling:
python -m pip install --upgrade -e '.[ai,dev]'
storage-log-analyzer --version
```

The AI extra now requires OpenAI SDK 3.x. Use a separate virtual environment if another application requires an older SDK. No package has been published to PyPI by this release process.

## v0.1.0

Initial vendor-aware CLI, local detection rules, redaction, and optional AI assessment.
