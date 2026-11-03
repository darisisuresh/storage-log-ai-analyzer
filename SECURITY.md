# Security Policy

## Reporting a vulnerability

Please email **darisi.suresh@ieee.org** with the subject `Storage Log AI Analyzer security report`. Do not publish exploit details, credentials, or customer logs in an issue. Include the affected commit/version, impact, and a minimal synthetic reproduction when possible.

## Security scope

The analyzer reads files supplied by the operator and writes reports locally. Ordinary analysis runs offline. `--ai` explicitly enables an external API request using a bounded, redacted finding summary. Local reports may still include original event evidence and file paths.

Redaction is heuristic. Review sanitized data before transmitting it. Protect API keys through environment variables and keep original customer logs, support bundles, and generated reports out of the repository.

Run analysis with the least privileges needed to read the intended log exports. Treat logs as untrusted input, and validate findings against vendor tools and original evidence. This project is an alpha operational aid; it is not a replacement for vendor support, a SIEM, or an incident-response process.

## Fixes

Include the exact commit or package version in a report so the issue can be reproduced. Check the default branch for fixes before retesting. No response-time or long-term-support commitment is implied.
