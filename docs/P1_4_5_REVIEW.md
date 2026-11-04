# P1-4 / P1-5 follow-up

The v0.4 baseline already removed file-wide vendor fallback and added strict JSONL,
malformed-record counters and private quarantine. This follow-up closes remaining
inconsistencies rather than reintroducing those features.

## Vendor attribution

Previously, summary/validation learned vendors online: a generic event could inherit
Pure before a later HPE hint for that device was seen. Analysis had a separate
whole-scan conflict check. Now ingestion stages events and learns device hints in
bounded-cache SQLite, then resolves inheritance consistently for every command.
Conflicts stay sticky across files and repeated hints. Multiple-vendor messages
remain ambiguous instead of selecting the highest hint score. Inventory keys are
case-insensitive and conflicting case aliases fail explicitly. Overrides and
explicit record metadata retain their documented precedence.

## JSONL validity

Strict parsing now rejects duplicate object keys, including nested keys, and numeric
overflow such as `1e999`, in addition to syntax errors, non-object records and
non-finite constants. Errors retain the physical file/line; quarantine retains the
rejected record. Lenient mode emits one stderr warning with the rejection count
and guidance, with no raw record content, while retaining counters and optional
quarantine. Strict failure precedes AI calls and leaves an existing output intact.

Verification covers late and cross-file vendor conflicts, syslog hosts, ambiguous
hints, inventory casing/precedence, all three CLI commands, nested duplicate keys,
numeric overflow, physical lines, quarantine, warnings, and strict output/AI safety.
No customer logs or external AI requests were used.

Local results (macOS/Python 3.14): 87 unit tests passed with ResourceWarnings
promoted to errors; Ruff and whitespace checks passed. The unchanged P0 text
benchmark verified exact counts for 100,000 events/incidents at 40.81 MiB peak RSS
(7.56 seconds), and 1,000,000 at 33.38 MiB (82.42 seconds). It passed the existing
128 MiB peak and 32 MiB growth limits. These measurements are synthetic local
checks, not throughput guarantees. The added staging pass increases temporary
disk usage and delays the first returned event; it does not retain all records in
application memory. `iter_file` remains the direct incremental parsing interface.
