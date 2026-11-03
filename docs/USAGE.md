# Operator procedure

This procedure covers installation, log preparation, offline analysis, AI-assisted analysis, and automation.

## 1. Install

```bash
git clone https://github.com/darisisuresh/storage-log-ai-analyzer.git
cd storage-log-ai-analyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Confirm the CLI is available:

```bash
storage-log-analyzer --version
storage-log-analyzer --help
storage-log-analyzer vendors
storage-log-analyzer rules
```

## 2. Collect and prepare logs

Export event, alert, audit, controller, capacity, drive, port, and replication logs from the storage management interface. Keep the original export read-only. Do not add real logs to this Git repository.

Place working copies in a separate directory, for example:

```text
/secure/storage-case-001/
  pure-alerts.log
  powerstore-events.csv
  alletra-audit.json
```

Accepted extensions are `.log`, `.txt`, `.csv`, `.json`, and `.jsonl`. Directory inputs are scanned recursively.

## 3. Validate before analysis

```bash
storage-log-analyzer validate /secure/storage-case-001
```

Use strict validation when building a repeatable parser pipeline:

```bash
storage-log-analyzer validate /secure/storage-case-001 --strict
```

Exit codes are `0` for valid, `1` for input/parsing failure, and `2` when strict validation finds unknown vendors or severities.

If vendor recognition is poor, force the known vendor:

```bash
storage-log-analyzer validate pure-alerts.log --vendor pure
```

## 4. Inspect the dataset

```bash
storage-log-analyzer summary /secure/storage-case-001
storage-log-analyzer summary /secure/storage-case-001 --format json -o summary.json
```

This reports file and event totals grouped by vendor, product, severity, and component.

## 5. Run offline analysis

Terminal report:

```bash
storage-log-analyzer analyze /secure/storage-case-001
```

Markdown incident report with only high and critical findings:

```bash
storage-log-analyzer analyze /secure/storage-case-001 \
  --min-severity high \
  --format markdown \
  --output reports/case-001.md
```

Machine-readable report for a SIEM or script:

```bash
storage-log-analyzer analyze /secure/storage-case-001 \
  --format json \
  --fail-on critical \
  --output reports/case-001.json
```

By default, `analyze` returns exit code `2` for high or critical risk. Set `--fail-on never` for interactive use or select a severity threshold for automation.

## 6. Make a sanitized copy

Before sharing a log with another team, create and review a redacted copy:

```bash
storage-log-analyzer redact pure-alerts.log -o sanitized/pure-alerts.log
```

The command refuses to overwrite the source. Current redaction covers IP addresses, email addresses, storage identifiers such as WWNs/serials/IQNs, and long hexadecimal IDs. It cannot guarantee removal of customer-specific free-form names, so manually review the result.

## 7. Optional AI-assisted assessment

AI mode is opt-in. Install the optional dependency and configure the key without committing it:

```bash
python -m pip install -e '.[ai]'
export OPENAI_API_KEY='your-key'
export STORAGE_LOG_AI_MODEL='gpt-5-mini'
storage-log-analyzer analyze /secure/storage-case-001 --ai --format markdown -o reports/ai-assessment.md
```

Only allowlisted aggregate counts, fixed rule metadata, state, and finding references are sent to the configured model. Raw evidence and identities are excluded. Preview the exact request with `analyze PATH --ai-preview -o request.json`. Review your organization's data-handling policy first. The original raw logs are not included in the AI request.

## 8. Use in automation

Example shell gate:

```bash
storage-log-analyzer analyze /var/log/storage --format json --output latest.json --fail-on high
case $? in
  0) echo "No high-risk finding" ;;
  1) echo "Analyzer or input error" ;;
  2) echo "High-risk storage finding; notify the on-call team" ;;
esac
```

Do not run AI mode unattended until secrets, retention, cost limits, and incident-response ownership are defined.

## 9. Triage findings

1. Preserve the original log export and record its collection time.
2. Confirm the affected array, controller, drive, port, pool, volume, or replication relationship.
3. Correlate findings with host multipathing, fabric, and storage-management events.
4. Validate current redundancy and the latest usable recovery point.
5. Escalate critical hardware, availability, or data-protection findings to the vendor.
6. For possible destructive activity, protect immutable recovery points and follow the incident-response plan.
7. Record false positives and add sanitized fixtures before changing a detection rule.

## Command reference

| Command | Purpose |
|---|---|
| `analyze PATH` | Detect risks and create a text, JSON, or Markdown report |
| `summary PATH` | Inventory events by vendor, product, severity, and component |
| `validate PATH` | Check readability and recognition coverage |
| `redact FILE -o FILE` | Create a sanitized copy without modifying the original |
| `rules` | List detection rule IDs, severities, and categories |
| `vendors` | List supported vendor families |
