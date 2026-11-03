# Changelog

## v0.2.0 — Dependency refresh and reliability fixes

### Updated packages

- Optional AI SDK: `openai>=3.42.1,<4` (previously `>=1.40,<3`).
- Build backend: `setuptools>=84.2.1,<85`; modern SPDX license metadata.
- Development tools: `ruff==0.17.3` and `build==1.6.1`.
- Base analysis still has no third-party runtime dependencies. Python 3.10+ remains supported.

### Fixes and additions

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
