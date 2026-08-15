# ThreatFade Enterprise Readiness

ThreatFade is an open-core security analytics platform. This document defines the production baseline and the controls that must be enabled by an operator before exposing the service to untrusted networks.

## Standards baseline

ThreatFade's engineering controls are aligned to OWASP ASVS 5.0, NIST CSF 2.0, secure software supply-chain practices, and least-privilege/container-hardening principles.

## Production controls

- TLS terminates at the deployment edge; plain HTTP is not exposed publicly.
- API authentication is mandatory in production (`THREATFADE_API_KEY` or an upstream OIDC gateway).
- CORS is allow-list based; wildcard origins are development-only.
- PCAP uploads have explicit byte limits and extension/content validation.
- Rate limiting is enabled and should be enforced at both edge and application layers.
- Request IDs are propagated through responses and audit records.
- Security response headers are emitted by the API.
- Secrets are supplied by a secret manager or deployment secret, never committed to Git.
- Containers run as a non-root user with a read-only filesystem where practical.
- Dependencies are reviewed and CI performs dependency/security checks.
- Releases should be signed and accompanied by SBOM/provenance in production distribution pipelines.
- Production telemetry must not contain secrets, raw PCAP payloads, authentication tokens, or unnecessary personal data.

## Identity and tenancy

The application security boundary is deliberately separated from the deployment identity provider. Enterprise deployments should place OIDC/SSO in front of the API or use the documented gateway contract. Tenant identity must be derived from an authenticated identity claim, never from an arbitrary client-controlled tenant header.

The public repository does not ship a hosted identity provider. Keycloak, Entra ID, Okta, Auth0, or an equivalent OIDC provider can be used at deployment time.

Recommended roles: `viewer`, `analyst`, `admin`, `tenant_admin`, `api_only`.

## Data protection

Treat uploaded PCAP and derived evidence as sensitive telemetry. Use encrypted object storage/database volumes, customer-specific retention, least-privilege access, and documented deletion procedures. Air-gapped deployments must disable external telemetry and use an offline dependency/release mirror.

## Reliability targets

Recommended initial SLOs:

- API availability: 99.9% monthly
- Health/readiness response: p95 < 250 ms
- Scenario detection: p95 < 2 s under the supported reference workload
- PCAP processing: workload-dependent and benchmarked before capacity commitments

These are service targets, not measured guarantees. Operators should record actual measurements before publishing them.

## Recovery

Production operators should maintain encrypted backups, periodically test restore procedures, and document RPO/RTO per customer tier. Multi-region deployment is an infrastructure responsibility and is intentionally not simulated in the community repository.

## Open-core boundary

Community code contains the detector, API, dashboard, interoperability formats, benchmark harness, and reference deployment assets. Commercial deployments may add managed identity, hosted storage, premium detection packs, support, managed integrations, and multi-region operations without weakening the community security model.
