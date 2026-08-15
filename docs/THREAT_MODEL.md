# ThreatFade Threat Model

## Assets

- Detection results and evidence
- Uploaded PCAP/PCAPNG files
- Detection packs and model artifacts
- API credentials and OIDC identity context
- Audit/operational telemetry
- Tenant configuration in enterprise deployments

## Trust boundaries

1. Internet/client -> reverse proxy/API
2. API -> PCAP parser/detection engine
3. Detection engine -> optional ML/model artifacts
4. API -> SIEM/FusionOps/webhook integrations
5. CI/release system -> published artifacts

## Primary threats

| Threat | Control |
|---|---|
| Malformed PCAP parser abuse | upload limits, validation, isolated workers, timeouts |
| Credential theft | secret manager, no secrets in Git, short-lived OIDC tokens |
| Cross-tenant access | authenticated tenant context, server-side authorization, isolated storage |
| Excessive resource consumption | rate limits, bounded inputs, worker quotas, backpressure |
| Supply-chain compromise | pinned/controlled dependencies, SCA, SBOM, signed releases |
| Dashboard XSS | avoid unsafe HTML interpolation; encode untrusted values |
| SSRF through integrations | explicit destination allow-lists and egress controls |
| Alert/evidence tampering | append-only audit trail and signed release/detection packs |
| Data leakage | retention policy, encryption, access controls, redaction |
| Model poisoning | signed/approved model artifacts and provenance |

## Security invariants

- Unauthenticated callers cannot execute protected detections in production.
- A client cannot select another tenant by changing a request field/header.
- Uploaded files never become executable files.
- Request and upload sizes are bounded.
- Secrets are never written to logs.
- Security failures fail closed.
- Optional integrations fail closed or degrade safely without disabling core detection.

## Abuse cases to test continuously

- Oversized uploads
- Invalid/malformed PCAPs
- Extremely long signal arrays
- NaN/Infinity numeric values
- CORS abuse
- Repeated authentication failures
- Path traversal filenames
- Slow clients / partial uploads
- Malicious detection-pack metadata
- Compromised external integration endpoints

Review this model whenever authentication, ingestion, integrations, storage, or execution boundaries change.
