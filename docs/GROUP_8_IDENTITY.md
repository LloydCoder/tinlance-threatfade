# Group 8 — Identity, Access Control & Enterprise Multi-Tenancy

**Status:** Implementation complete pending hosted CI/security verification  
**Baseline:** ThreatFade v0.7.x  
**Scope:** Authentication boundary, authorization, tenant isolation, privileged operations and identity regression controls.

## Implemented controls

### Authentication boundary

- Production protected operations require a Bearer OIDC access token.
- API-key authentication is not a production fallback.
- Development authentication is explicitly environment-gated.
- Authorization schemes other than Bearer are rejected.

### JWT validation

- Required claims: `iss`, `aud`, `sub`, `iat`, `exp`.
- Issuer and audience are verified.
- Expiry and issued-at are verified with bounded clock skew.
- RSA signing algorithms are explicitly allow-listed (`RS256`, `RS384`, `RS512`).
- JWT `kid` is required and matched against JWKS.
- JWKS signing-key type/use/algorithm are validated.
- JWKS retrieval uses short connect/read timeouts and does not follow redirects.
- Unknown signing keys trigger one bounded JWKS refresh for rotation support.
- Access-token length is bounded.

### Authorization

- Roles are explicit and allow-listed.
- Permissions are derived from roles/scopes.
- Unsupported role/scopes are not elevated implicitly.
- Viewer/analyst/API-only/tenant-admin/admin capabilities remain distinct.

### Tenant isolation

- Tenant identifiers have a strict allow-list format.
- Authenticated token tenant is authoritative.
- `X-Tenant-ID` is only a consistency assertion.
- Cross-tenant access is denied by default.
- The ordinary `admin` role is tenant-scoped.
- Cross-tenant access requires an explicit `global_admin=true` claim.

### Service-to-service boundary

No current production endpoint requires a machine-only principal. The Group 8 boundary therefore does not advertise an unexercised service-token contract. When service-only endpoints are introduced, they must use short-lived OIDC service identities with explicit least-privilege authorization rather than inheriting human administrator privileges.

## Regression coverage

`tests/test_enterprise_security.py` covers:

- role permission boundaries
- cross-tenant denial
- explicit global-admin delegation
- tenant identifier validation
- production authentication fail-closed behavior
- API-key exclusion from production authentication
- Bearer scheme enforcement
- JWT algorithm allow-list
- malformed role claims
- namespaced OIDC roles/tenant claims
- unknown signing keys
- HS256 rejection

`test_enterprise.py` also enforces that the `admin` role alone cannot cross tenant boundaries; cross-tenant administration requires the explicit `global_admin=true` claim.

`scripts/validate_identity_architecture.py` provides a deterministic CI architecture gate against accidental removal of the production OIDC boundary, tenant isolation rule, RSA algorithm allow-list, issuer/audience verification and bounded JWKS retrieval.

## Verification boundary

This group establishes the application-level identity and authorization baseline. It does **not** constitute independent penetration testing, certification, or proof that a particular customer identity provider is configured securely. Deployment-specific IdP configuration, TLS, secret management, conditional access, MFA and administrative lifecycle remain deployment/customer controls.
