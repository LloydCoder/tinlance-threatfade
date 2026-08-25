# ADR 0003 — Identity and Tenant Boundary

## Decision

ThreatFade uses a standards-based OIDC identity provider for authentication and keeps customer authorization state inside the ThreatFade engine.

The web application is a server-side relying-party/BFF layer. The engine is the authorization source of truth for organizations, memberships, roles, tenant selection and session revocation.

## Why

ThreatFade should not create a second password authority, should not trust browser-supplied tenant IDs, and should not duplicate authorization state between the web and engine repositories.

OIDC provides the authentication protocol boundary. ThreatFade stores only the identity subject and application-specific membership/session state.

## RBAC

The customer roles are owner, admin, analyst and viewer. Permissions are derived server-side from the membership stored for the requested organization. A user can have different roles in different organizations.

## Tenant isolation

Every authenticated engine operation resolves the requested organization against the caller's membership before permission evaluation. Existing detection and SOC data-plane tables continue to carry their `tenant_id` and existing PostgreSQL RLS controls. The Phase 13 identity tables are control-plane records and are protected through application-level subject/membership authorization rather than recursively self-referential RLS policies.

## Session model

Auth.js owns the browser cookie. ThreatFade owns an opaque server session token. Only a hash of the opaque token is stored. The web BFF forwards both the OIDC access token and opaque session token over the private server-to-server boundary. Revocation is enforced by the engine on every request that presents the session token.

## Rejected alternatives

- Password authentication inside ThreatFade: rejected; duplicates identity security and increases credential attack surface.
- Client-side role/tenant claims as authorization source: rejected; violates server-side authorization and IDOR protections.
- Separate tenant authorization database in the web repository: rejected; would create split-brain authorization state.
- Self-issued long-lived browser bearer tokens: rejected; server-revocable session tokens provide stronger lifecycle control.
- Native WebAuthn implementation in the web app for Phase 13: deferred; enterprise passkeys/MFA should be supplied by the configured OIDC provider first.
