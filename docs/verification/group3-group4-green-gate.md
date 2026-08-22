# Group 3 + Group 4 Verification Gate

This marker exists only to exercise the complete hosted CI/security pipeline against the final enterprise-hardening baseline.

Required gate: all Python matrix tests, PostgreSQL RLS/integrity verification, dependency audit, CodeQL, secret scanning, detection-pack validation, benchmark regression and production container build must be green.

The RLS acceptance test deliberately runs as a non-owner, non-BYPASSRLS application role; the migration owner is used only for schema installation.
