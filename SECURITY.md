# Security Policy

## Reporting a vulnerability

Please email **darisi.suresh@ieee.org** with the subject `Storage Log AI Analyzer security report`. Do not publish exploit details, credentials, or customer logs in an issue. Include the affected commit/version, impact, and a minimal synthetic reproduction when possible.

## Security scope

The analyzer reads files supplied by the operator and writes reports locally. Ordinary analysis runs offline. `--ai` explicitly enables an external API request using allowlisted aggregate facts; raw evidence, paths, and identities are excluded. Local reports may still include original event evidence and file paths.

Redaction is heuristic. Review sanitized data before transmitting it. Protect API keys through environment variables and keep original customer logs, support bundles, and generated reports out of the repository.

A temporary local SQLite database holds incident state and bounded evidence samples during analysis and is cleaned up on completion or failure. It is not encrypted; use a private temporary directory with sufficient space. Input record/nesting/identity limits bound individual records.

Run analysis with the least privileges needed to read the intended log exports. Treat logs as untrusted input, and validate findings against vendor tools and original evidence. This project is an alpha operational aid; it is not a replacement for vendor support, a SIEM, or an incident-response process.

## Fixes

Include the exact commit or package version in a report so the issue can be reproduced. Check the default branch for fixes before retesting. No response-time or long-term-support commitment is implied.


## Structured AI and local parsing controls (v0.4.0)

AI is limited to approved local finding references and action codes. Unknown references, contradictory states, extra claims, invented confidence scores and incomplete output are rejected before rendering. Raw log text is excluded from both prompt and schema. The output-token budget is bounded; failures preserve the local report.

`--quarantine` is opt-in and writes raw rejected records to a private local file outside the input directory. Do not share it without review. Device inventory is operator-supplied local configuration, not an authenticated source of business impact. UTC assumptions and invalid timestamps are visible in diagnostics.

Scratch databases are cleaned on normal completion and handled exceptions. Abrupt termination can leave private temporary directories; they are not encrypted evidence archives.
