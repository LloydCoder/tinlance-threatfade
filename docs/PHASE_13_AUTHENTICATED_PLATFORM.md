# Phase 13 — Authenticated Platform

## Status

Implementation target: authenticated customer platform foundation.

Phase 13 establishes the identity/control-plane boundary required by the Phase 12 SOC workspace. The public/open-core engine remains usable without a customer organization; authenticated enterprise resources require an OIDC identity plus a server-side organization membership.

## Architecture

`Browser → Next.js 16 Proxy → Auth.js OIDC session → Next.js server BFF → ThreatFade engine → tenant-scoped persistence`

The browser never supplies a role or tenant as an authorization decision. The web application stores its session in an HttpOnly cookie. The encrypted Auth.js JWT contains the OIDC access token and an opaque ThreatFade session token; neither is exposed through the client session object. The engine stores only a SHA-256 hash of the opaque session token.

### OIDC

- Authorization Code flow.
- PKCE S256, state and nonce checks are enabled by the authentication framework.
- Provider issuer is fixed by `THREATFADE_OIDC_ISSUER` and discovery metadata.
- Token endpoint is fixed by `THREATFADE_OIDC_TOKEN_URL`.
- Redirect targets are same-origin only; arbitrary callback URLs are rejected.
- The engine validates `iss`, `aud`, `exp`, `iat`, signature algorithm and signing key.
- Production accepts only RSA-signed OIDC JWTs from the configured issuer/audience.

### Session

- Browser session: secure, HttpOnly, SameSite=Lax cookie.
- Application session: opaque random token, 256-bit class entropy, hashed at rest.
- Idle/absolute browser session lifetime: 8 hours, with a 15-minute JWT update window.
- Engine session lifetime: 8 hours, bounded to 12 hours maximum.
- Logout revokes the engine session and clears the browser cookie.
- Sign-out-everywhere revokes all active engine sessions for the subject.
- Disabled identities cannot establish or retain an engine session.

### Organizations and tenant model

An organization ID is the canonical ThreatFade tenant identifier. Membership is the authorization relationship between an authenticated subject and an organization.

Roles:

| Role | Detection read | Detection run | Case read | Case write | Organization/member management |
|---|---:|---:|---:|---:|---:|
| owner | yes | yes | yes | yes | yes |
| admin | yes | yes | yes | yes | yes |
| analyst | yes | yes | yes | yes | no |
| viewer | yes | no | yes | no | no |

The engine resolves the requested tenant against the authenticated subject's membership before permission evaluation. A guessed organization/detection identifier without membership is denied.

## Invitations

Invitation tokens are random, single-use, seven-day tokens. Only a SHA-256 hash is persisted. Acceptance requires the authenticated identity's email to match the invitation email. Owners/admins can create and revoke invitations. The application does not silently link accounts by email across identity providers.

The web settings UI intentionally displays a newly generated invitation token once so an enterprise deployment can deliver it through its approved communication channel. A future mail integration can consume the same server-side invitation primitive without changing authorization semantics.

## Security controls

- Deny-by-default server-side authorization.
- Object-level tenant membership checks on every authenticated resource request.
- No client-only role enforcement.
- No browser-supplied Authorization header is accepted by the web SOC BFF.
- Same-origin checks on state-changing BFF requests.
- Upstream HTTPS enforcement in production.
- Upstream redirects disabled.
- Request/response body bounds and timeouts.
- Generic authentication/authorization errors.
- Authentication and authorization events are audited.
- Public marketing/research routes remain outside the authenticated boundary.

## Required adversarial tests

The Phase 13 suite covers:

- cross-tenant membership denial;
- horizontal privilege escalation denial;
- owner/admin/analyst/viewer permission boundaries;
- invitation email binding and single-use semantics;
- server-side session revocation;
- disabled-account session denial;
- invalid OIDC signature/algorithm/issuer/audience handling;
- open-redirect prevention at the web callback boundary;
- same-origin mutation enforcement;
- client Authorization-header spoofing prevention at the web BFF.

## External deployment requirements

A production customer deployment must configure:

- `NEXTAUTH_SECRET` with a high-entropy secret;
- `THREATFADE_OIDC_ISSUER`;
- `THREATFADE_OIDC_CLIENT_ID`;
- `THREATFADE_OIDC_CLIENT_SECRET`;
- `THREATFADE_OIDC_TOKEN_URL`;
- `THREATFADE_API_URL` over HTTPS;
- engine `THREATFADE_OIDC_ISSUER`, `THREATFADE_OIDC_AUDIENCE`, and `THREATFADE_OIDC_JWKS_URL`;
- a production PostgreSQL database migrated through Alembic.

The public Vercel deployment must not expose the SOC routes as a public demo until those identity-provider and engine environment variables are configured.

## Assurance boundary

Passing repository tests demonstrates implementation correctness for the covered cases. It is not a substitute for an independent penetration test, identity-provider configuration review, customer-scale load test, or WebAuthn/passkey rollout. WebAuthn/passkeys are intentionally delegated to the OIDC identity provider in Phase 13 rather than implemented as a second credential authority inside ThreatFade.
