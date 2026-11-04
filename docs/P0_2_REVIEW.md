# P0-2 sensitive-data protection follow-up

The original review requested schema-aware redaction, configurable allowlists,
correlation-preserving aliases, sensitive-field tests, and an exact AI preview.
The v0.3/v0.4 AI boundary already excludes evidence and arbitrary input fields;
this change completes the local export follow-up without widening that boundary.

- Recursively redact JSON fields after decoding escaped strings; keep nested
  objects, lists, counts and booleans valid.
- Normalize vendor field spelling; add serial numbers, service tags, WWNN,
  tenant/customer names, share names, and credential variants.
- Recognize standalone NAA, IQN and colon-separated WWN identifiers.
- Use keyed aliases shared across lines of one export, with a fresh key per export
  and no retained identity map. Aliases intentionally differ between exports.
- Provide repeatable local identity allowlists and additional JSON sensitive fields.
  Credential fields and credential patterns cannot be allowlisted.
- Preserve the existing aggregate-only AI schema, structural finding limit,
  provider-free exact request preview, atomic output, and per-record input limit.

Validation: 82 unit tests, including new nested/escaped JSON, vendor identifiers,
credential allowlist rejection, JSONL correlation and export isolation cases;
Ruff lint checks passed. Existing provider-boundary and request-preview tests pass.
No external AI requests or customer logs were used.
