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

## 6. Offline and store-and-forward boundary

The repository implements bounded durable store-and-forward and signed/replay-safe delivery paths. Offline operation is therefore bounded, not unlimited: capacity, retry, retention, and deployment durability depend on the configured storage/queue environment. Optional enrichment may degrade without disabling core detection, but degradation must remain observable.

## 7. Input and resource security

PCAP/PCAPNG, network signals, detection packs, model artifacts, and integration payloads are treated as untrusted or security-sensitive inputs. The architecture requires schema validation, bounded parsing/processing, path safety, timeouts, rate limits, and explicit resource bounds. Uploaded capture content is data, not executable content.

## 8. Supply-chain security

The repository contains dependency/security scanning, SBOM, provenance/attestation, artifact signing, container hardening, and release verification gates. These are implemented engineering controls; they are not evidence of a third-party security certification.

## 9. Deployment responsibilities

ThreatFade's deployment architecture separates application controls from operator responsibilities. Operators remain responsible for TLS/edge controls, secret management, PostgreSQL encryption/HA/backups, immutable evidence/audit retention, network segmentation, egress policy, runtime resource limits, and identity-provider configuration.

## 10. Assurance boundary

This architecture is an engineering baseline. It does **not** represent SOC 2, ISO 27001, Common Criteria, regulatory approval, third-party penetration testing, independent detection validation, or customer-scale assurance. Those require separate evidence.
