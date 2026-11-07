# Contributing to ThreatFade

Thank you for considering a contribution. ThreatFade is a security-sensitive detection and investigation project; correctness, evidence integrity, tenant isolation and safe failure behavior are part of the contribution contract.

## Before opening an issue

- Search [existing issues](https://github.com/LloydCoder/tinlance-threatfade/issues).
- Use the structured bug or feature form.
- Do not publish credentials, private keys, customer data, sensitive PCAPs or vulnerability exploit details.
- For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md), not a public issue.

## Development setup

The repository's supported CI test matrix currently covers Python 3.11 and 3.12.

```bash
git clone https://github.com/LloydCoder/tinlance-threatfade.git
cd tinlance-threatfade
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell activation:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Branch and pull-request workflow

1. Fork the repository.
2. Create a focused branch from an up-to-date `main`, for example `fix/tenant-boundary-check` or `docs/configuration-reference`.
3. Make the smallest coherent change that addresses the issue.
4. Add or update regression tests for behavior changes.
5. Run relevant tests and validators locally.
6. Update user-facing documentation and `CHANGELOG.md` when behavior, configuration, compatibility or release notes change.
7. Push the branch and open a pull request using the repository template.
8. Respond to review feedback and ensure all required CI checks pass before merge.

## Engineering standards

- Python: follow PEP 8 conventions and use clear names, type hints and focused functions.
- Architecture: preserve separation between detection/data-plane work and authenticated control-plane concerns.
- Security: validate untrusted inputs, bound resource consumption, fail closed at authentication/authorization boundaries and avoid logging secrets.
- Multi-tenancy: derive tenant identity from the authenticated server-side principal; never trust a browser-supplied tenant identifier as authority.
- Evidence: preserve provenance and integrity; do not silently rewrite or discard evidence metadata.
- Integrations: use the shared transport and credential-provider boundaries; do not persist credentials in events or configuration committed to Git.
- ML: keep experimental models separate from authoritative production detection unless promotion criteria and independent evidence are satisfied.
- Documentation: label synthetic, experimental, adapter-only and external-assurance claims accurately.
- Dependencies: justify new runtime dependencies and review license, maintenance, security and supply-chain impact.

## Testing and validation

Run the complete Python suite:

```bash
python -m pytest -q
```

For focused work, run the relevant test module(s), then run the full suite before requesting merge. CI additionally executes architecture validators, PostgreSQL migration/schema checks, repeated test execution, benchmark suites, integration checks, CodeQL, secret scanning, dependency auditing and container/supply-chain validation.

Relevant validator examples:

```bash
python scripts/validate_security_architecture.py
python scripts/validate_identity_architecture.py
python scripts/validate_supply_chain.py
python scripts/validate_ground_truth.py
```

Not every validator is relevant to every change. Report exactly which commands you ran and their results; do not claim that a test passed if it was not executed.

## Commit messages

Use the Conventional Commits style used by the repository history:

- `feat:` new capability
- `fix:` defect correction
- `docs:` documentation-only change
- `test:` test-only change
- `build:` dependency or build-system change
- `ci:` workflow change
- `refactor:` behavior-preserving restructuring

Keep commits focused and describe the user-visible or engineering outcome.

## Security-sensitive contributions

Changes affecting authentication, authorization, tenant isolation, cryptographic verification, evidence handling, hostile file parsing, outbound requests, secret handling or release workflows require explicit security review. Add negative tests for unauthorized, malformed, replayed, oversized and cross-tenant inputs where applicable.

Do not test against systems or data you do not own or have permission to assess. Never commit real credentials, production data, packet captures containing sensitive information or private vulnerability details.

## Documentation and release hygiene

- Update `README.md` for user-facing behavior or onboarding changes.
- Update `docs/reference/configuration.md` when configuration changes.
- Update the relevant architecture, deployment or operational guide.
- Update `CHANGELOG.md` for notable changes.
- Keep the public capability and evidence boundary aligned with `docs/public-truth.json`.

## Review and merge

A pull request may be merged only after required checks are green, review feedback is resolved, and compatibility/security implications are understood. Passing CI is necessary evidence, not proof of independent security assurance or production detection effectiveness.

Thank you for helping improve ThreatFade.
