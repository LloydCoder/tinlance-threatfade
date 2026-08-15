# ThreatFade Enterprise Implementation

ThreatFade's enterprise profile is implemented around NIST CSF 2.0 governance, OWASP ASVS 5.0 application security, OpenID Connect/OAuth 2.0 security best practice, and modern software-supply-chain controls.

## Implemented in the repository

- Native OIDC bearer-token validation using issuer, audience, JWKS, expiry and issuer checks.
- RBAC roles: viewer, analyst, API-only, admin and tenant admin.
- Tenant context on every persisted detection; cross-tenant access is denied unless explicitly privileged.
- Durable persistence through SQLAlchemy; PostgreSQL is the production reference database and SQLite is for development.
- Append-only structured audit events with tenant, subject, action, request ID and source IP.
- Production fail-closed authentication: an enterprise OIDC token is required.
- Bounded PCAP/request inputs and rate limiting.
- Production security headers and restrictive CORS.
- Readiness endpoint exposing configured SLO targets.
- Investigation case persistence primitives.
- Production Docker Compose topology with PostgreSQL and persistent audit storage.
- Kubernetes deployment baseline.
- CI tests, benchmarks, dashboard smoke tests, CodeQL, secret scanning and dependency auditing.
- Container SBOM/provenance and keyless signing on versioned releases.

## Enterprise operating requirements

The codebase cannot honestly manufacture external assurance. The following are operational/customer-delivery activities and must be completed against the actual production environment:

1. Register the organization's OIDC application and configure exact redirect URIs.
2. Use a managed PostgreSQL HA deployment with encryption, backups and tested restore.
3. Put audit output in immutable/WORM storage and centralize logs.
4. Configure secrets through a production secret manager; never commit credentials.
5. Run a third-party penetration test and independent purple-team/detection validation.
6. Establish a customer-labeled validation corpus and publish confidence intervals and dataset provenance.
7. Run load tests against the target topology and record measured p50/p95/p99 latency and throughput.
8. Define contractual SLO/SLA targets and incident-response commitments.
9. Configure multi-region disaster recovery where the customer's RTO/RPO requires it.
10. Complete legal/commercial controls for data residency, retention, DPA, support and licensing.

These items are deliberately separated from source-code controls: a repository can implement the technical mechanisms, but cannot truthfully claim an independent audit, third-party validation, production scale or contractual SLA until those activities have occurred.
