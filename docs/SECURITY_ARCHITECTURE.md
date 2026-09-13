# ThreatFade Security Architecture

**Status:** Group 1 / Build 15 — complete baseline  
**Version:** 1.2  
**Scope:** ThreatFade v0.9.0-dev repository and reference deployment architecture  
**Security reference:** OWASP ASVS 5.0.0 is used as an application-security verification baseline, with stronger controls applied where ThreatFade's security-monitoring, evidence, ingestion, or multi-tenant risk justifies them. This is an engineering baseline, not a certification claim.

## 1. Purpose

This document defines ThreatFade's security architecture, trust boundaries, security invariants, principal classes, data flows, security responsibilities, and architectural assumptions. It is the normative companion to `docs/THREAT_MODEL.md` and `docs/ASVS_5.0_MATRIX.md`.

ThreatFade is a security-sensitive detection and investigation platform. The most important security property is **integrity of detections and evidence under hostile input and hostile tenancy**.

## 2. Security objectives

1. Prevent unauthenticated or unauthorized execution of protected operations in production.
2. Prevent cross-tenant data access and tenant-context substitution.
3. Treat PCAP, network signals, detection packs, model artifacts, and integration payloads as untrusted or security-sensitive inputs unless explicitly trusted.
4. Preserve the integrity, provenance, and auditability of detections and evidence.
5. Bound resource consumption so hostile input cannot trivially exhaust API, parser, worker, or database resources.
6. Ensure security failures fail closed at authentication and authorization boundaries.
7. Make security controls testable and traceable to requirements.
8. Preserve offline/air-gapped operation without weakening the core security model.
9. Maintain a verifiable software supply chain from source revision to release artifact.

## 3. Security zones and trust boundaries

```text
Internet / customer network
        |
        v
Reverse proxy / TLS edge
        |
        v
ThreatFade API / control plane <---- Enterprise IdP / OIDC
        |
        +---- bounded detection workload ----> detection + evidence engine
        |                                           |
        +---- analyst console                    evidence / audit storage
        |                                           |
        +---- durable queue (reference)             +---- PostgreSQL
        |
        +---- normalized integration transport ---> SIEM / SOAR / FusionOps

Protected source -> CI security gates -> SBOM/provenance/signature -> artifact registry
```

### Trust boundaries

| ID | Boundary | Untrusted input | Required control family |
|---|---|---|---|
| TB-01 | Customer/client → edge/API | HTTP headers, body, auth tokens, files | TLS, authentication, validation, rate limits, request limits |
| TB-02 | API → identity provider | discovery/JWKS/token metadata | issuer/audience validation, algorithm allowlist, time validation, bounded network calls |
| TB-03 | API → detection workload | signals, scenario names, PCAP jobs | schema validation, resource limits, worker isolation, timeouts |
| TB-04 | PCAP parser → detection engine | packet structures and payload-derived values | parser isolation, bounded parsing, normalization, provenance |
| TB-05 | Tenant context → persistence | tenant identifiers and authorization claims | server-derived tenant context, authorization, database RLS in enterprise deployment |
| TB-06 | Detection engine → integrations | generated exports and outbound destinations | explicit allowlists, egress policy, output validation |
| TB-07 | Detection/model packs → runtime | rule/model artifacts | signing, approval, provenance, compatibility validation |
| TB-08 | Source/CI → release artifact | source, dependencies, build configuration | protected branches, dependency controls, SBOM, provenance, signing |
| TB-09 | Analyst console → API | analyst-controlled actions and display values | authorization, output encoding, CSRF/session controls where applicable |
| TB-10 | API → browser/dashboard rendering | detection/evidence text, tenant data, analyst-controlled values | server-side authorization, contextual output encoding, safe DOM rendering, CSP/security headers |

## 4. Identity and authorization

The repository defines authenticated tenant viewers, analysts, tenant administrators, platform administrators, scoped service identities, constrained detection workers, and CI/release identities. Protected operations are intended to fail closed when the identity boundary is missing or invalid. Tenant authority is derived from authenticated identity and server-side authorization rather than browser-controlled tenant identifiers.

OIDC/JWT is an external dependency in protected deployments. The security architecture requires issuer/audience validation, an algorithm allowlist, time validation, bounded identity-provider calls, and JWKS validation where configured.

## 5. Evidence integrity and auditability

ThreatFade treats detection integrity and provenance as security properties. Evidence records are designed to retain enough provenance to reconstruct the input source, detection rule/version, engine version, configuration, and evidence used to produce a detection. Security-sensitive authorization, detection, export, administrative, and configuration actions produce structured audit events.

Cryptographic integrity controls, signed batches, replay protection, and offline evidence packaging are documented in the repository's evidence/integrity implementation. A log entry is not treated as equivalent to a cryptographic signature or hash chain.

## 6. Offline and store-and-forward security

The repository implements bounded durable store-and-forward and signed/replay-safe delivery paths. Offline operation is therefore bounded, not unlimited: capacity, retry, retention, and deployment durability depend on the configured storage/queue environment. Optional enrichment may degrade without disabling core detection, but degradation must remain observable.

## 7. Security invariants

- **SI-01 Authentication boundary:** production protected operations require a valid configured identity boundary; missing or invalid identity configuration fails closed.
- **SI-02 Tenant authority:** client-controlled tenant identifiers cannot grant authority over another tenant.
- **SI-03 Privilege separation:** platform-wide privileges are distinct from tenant-scoped privileges and require explicit role assignment.
- **SI-04 Untrusted file handling:** uploaded PCAP/PCAPNG content is data, never executable content; arbitrary client filenames are not trusted as filesystem paths.
- **SI-05 Evidence integrity:** detections retain sufficient provenance to reproduce their source, rule/version, engine version, configuration and evidence boundary.
- **SI-06 Audit integrity:** security-sensitive actions generate structured audit events; durable tamper-evident centralized retention is a deployment responsibility.
- **SI-07 Fail closed:** authentication, authorization and tenant-isolation boundaries fail closed.
- **SI-08 Bounded processing:** externally controllable resource-intensive operations have explicit size/count/time/memory/concurrency/rate bounds.
- **SI-09 Supply-chain integrity:** release artifacts are traceable to source with SBOM/provenance/signing controls.
- **SI-10 Secrets non-disclosure:** credentials, tokens, raw PCAP payloads and restricted evidence are not emitted to public telemetry or application logs.

## 8. Input and resource security

PCAP/PCAPNG, network signals, detection packs, model artifacts and integration payloads are treated as untrusted or security-sensitive inputs. The implementation and deployment model use schema validation, bounded parsing/processing, path safety, timeouts, rate limits, request IDs, CORS/security-header controls and explicit resource limits. Uploaded capture content is data, not executable content.

## 9. Supply-chain security

The repository contains dependency/security scanning, SBOM generation, provenance/attestation, artifact signing, container hardening and release verification gates. These are implemented engineering controls; they are not evidence of a third-party security certification.

## 10. High-risk design decisions

| Decision | Rationale | Residual risk |
|---|---|---|
| PostgreSQL is the production reference store | Durable relational tenancy and investigation state | HA, backup, encryption and operational RLS remain deployment responsibilities until independently verified in the target environment |
| PCAP parsing is a security boundary | Network captures are attacker-controlled data | The synchronous reference path still requires deployment-level workload isolation for stronger sandboxing |
| OIDC is externalized | Enterprise identity belongs at the customer's trust boundary | Provider configuration remains an operational risk |
| Detection packs are versioned | Detection behavior must be reproducible | Full signing/registry/canary lifecycle remains a follow-on control area |
| Optional telemetry is not required for core detection | Detection should not depend on an observability provider | Production telemetry policy remains operator-controlled |

## 11. Deployment responsibilities

ThreatFade's deployment architecture separates application controls from operator responsibilities. Operators remain responsible for TLS/edge controls, secret management, PostgreSQL encryption/HA/backups, immutable evidence/audit retention, network segmentation, egress policy, runtime resource limits and identity-provider configuration.

## 12. Assurance boundary

This architecture is an engineering baseline. It does **not** represent SOC 2, ISO 27001, Common Criteria, regulatory approval, third-party penetration testing, independent detection validation, contractual SLAs or customer-scale assurance. Those require separate operational and independent evidence.
