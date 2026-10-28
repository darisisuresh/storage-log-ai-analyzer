# Contributing

Contributions for additional arrays, firmware versions, and log formats are welcome.

1. Create a focused branch.
2. Add only sanitized or synthetic log fixtures.
3. Add vendor/product hints in `src/storage_log_analyzer/vendors.py` or detection rules in `rules.py`.
4. Add tests that demonstrate the expected normalized event or finding.
5. Run `python -m unittest discover -s tests -v` and `ruff check .`.

Do not submit customer logs, credentials, network addresses, serial numbers, WWNs, hostnames, or support bundles. Describe false positives and false negatives in the pull request.
