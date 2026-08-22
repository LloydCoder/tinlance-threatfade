# ThreatFade Enterprise Build Status

**Program:** Enterprise Hardening  
**Current release baseline:** v0.7.0  
**Current group:** Group 8 — Identity, Access Control & Enterprise Multi-Tenancy  
**Current build:** Build 52  
**Status:** IMPLEMENTATION COMPLETE — hosted CI/security verification is the release gate

## Completed groups

- Group 1 — Security Architecture & Threat Model: ✅ Builds 15–17
- Group 2 — Detection Science & Validation: ✅ Builds 18–23
- Group 3 — Detection Pack Platform: ✅ Builds 24–27
- Group 4 — Data Integrity, Evidence & Audit: ✅ Builds 28–33
- Group 5 — Reliability, Observability & Resilience: ✅ Builds 34–37
- Group 6 — Disaster Recovery, Backup & Operational Continuity: ✅ Builds 38–41
- Group 7 — Secure Deployment, Supply Chain & Production Operations: ✅ Builds 42–46

## Group 8 — Identity, Access Control & Enterprise Multi-Tenancy

| Build | Deliverable | Status |
|---|---|---|
| 47 | Authentication boundary review and production OIDC fail-closed behavior | 🟢 Implemented |
| 48 | Tenant authority enforcement and cross-tenant regression coverage | 🟢 Implemented |
| 49 | JWT/JWKS hardening: issuer, audience, required claims, RSA algorithm allow-list, key rotation and bounded retrieval | 🟢 Implemented |
| 50 | Explicit RBAC/scopes and privileged-operation separation | 🟢 Implemented |
| 51 | Tenant identifier validation, request consistency checks and audit auth-method attribution | 🟢 Implemented |
| 52 | Identity architecture CI gate and dedicated security regression suite | 🟢 Implemented |

### Group 8 evidence

- `core/enterprise.py`
- `tests/test_enterprise_security.py`
- `scripts/validate_identity_architecture.py`
- `.github/workflows/ci.yml`
- `docs/GROUP_8_IDENTITY.md`
- `docs/ENTERPRISE_READINESS.md`

### Group 8 acceptance gate

- [x] Production protected operations require Bearer OIDC authentication.
- [x] API-key authentication cannot be used as a production fallback.
- [x] Development authentication is environment-gated and cannot activate in production.
- [x] JWT issuer and audience are verified.
- [x] JWT `iss`, `aud`, `sub`, `iat`, and `exp` are required.
- [x] Only RSA `RS256`, `RS384`, and `RS512` algorithms are accepted.
- [x] JWT `kid` is required and matched against the configured JWKS.
- [x] JWKS retrieval is bounded and redirects are disabled.
- [x] Unknown signing keys trigger one bounded refresh for key rotation.
- [x] Roles are allow-listed and permissions are explicit.
- [x] Tenant identifiers are validated against a strict format.
- [x] Authenticated token tenant is authoritative.
- [x] Cross-tenant access is denied unless explicitly delegated with `global_admin=true`.
- [x] Ordinary tenant `admin` is not a cross-tenant privilege.
- [x] Identity and tenant-boundary regressions are covered by executable tests.
- [x] Identity architecture controls are enforced by CI.

## Verification boundary

Automated tests and CI demonstrate implementation and regression evidence. They do not constitute independent penetration testing, SOC 2/ISO certification, independent detection validation, contractual SLAs, provider-specific PITR guarantees, or customer-scale performance guarantees.

Service-to-service identity remains an extension point: no current production endpoint requires a machine-only principal, so the repository does not advertise an unexercised service-token contract. When service-only endpoints are introduced, they must use a short-lived OIDC service principal and explicit least-privilege authorization.

## Next planned group

**Group 9 — ThreatFade Detection Science 2.0.**

Initial focus: canonical feature extraction, flow/session reconstruction, beacon/jitter modeling, fade-window modeling, adaptive baselines, protocol-aware encrypted-traffic metadata, ensemble detection and calibration.
