# Changelog

All notable changes to ThreatFade will be documented in this file.

## Unreleased — Phase 3 Production SOC / Analyst Platform

### Added
- Tenant-scoped detection inbox with bounded filtering and workflow state.
- Investigation workspace for detection assessment, evidence review and analyst actions.
- Evidence-centric investigation timeline preserving provenance hashes and timestamps.
- Correlation-scoped entity and session explorer primitives.
- Detection-to-case linking and case-aware disposition workflow.
- Explicit analyst disposition reasons and bounded analyst notes.
- Server-side web-to-engine analyst API boundary; browser clients never receive engine credentials or choose the tenant.
- Same-origin protection for mutating analyst proxy requests when an Origin header is supplied.
- Durable workflow/disposition records and audit events with tenant isolation.
- PostgreSQL migration and row-level-security policies for new analyst workflow tables.
- Automated analyst workflow tests covering tenant isolation and invalid state/disposition inputs.

### Evidence boundary
- Phase 3 is **implemented — repository validation pending** until engine and web CI/security/end-to-end gates pass.
- Analyst confidence and detection score are assessments, not evidence.
- Investigation correlation does not establish causality or attribution.
- FusionOps contracts are preserved; external end-to-end handoff remains deployment validation.

## Unreleased — Phase 2 Resilient Transport and Offline Evidence

### Added
- Bounded SQLite-backed store-and-forward queue after the canonical Group 11 `SignalEvent` boundary.
- Explicit event/byte limits, seven-day default retention and priority-aware eviction.
- Bandwidth-aware batch selection with bounded byte budgets and no destructive acknowledgement before transport success.
- Monotonic sensor-local event sequencing and durable per-tenant/per-sensor replay cursors.
- Idempotent batch IDs and explicit duplicate/replay/gap outcomes.
- Signed batch envelopes using Ed25519.
- Portable ThreatFade Evidence Package v1 with manifest, event/evidence hashes, provenance, sensor/tenant identity and signature metadata.
- Offline package verification without control-plane network access.
- Persistent signing trust store with additive key rotation and explicit revocation.
- Hostile-condition tests for disk/resource bounds, tampering, tenant mismatch, replay, duplicate delivery, sequence gaps, expiry and revocation.
- Reproducible air-gap validation workflow.

### Evidence boundary
- Phase 2 is **implemented — repository validated; production deployment soak not yet established**.
- Cryptographic verification proves integrity/authenticity of signed bytes; it does not prove sensor truth, maliciousness or causal attribution.
- Repository air-gap validation does not substitute for production PKI/HSM/key-management validation.

## Unreleased — Phase 1 Multi-Domain Fade Correlation

### Added
- Reusable `CorrelationObservation` model over canonical `SignalEvent` data.
- Deterministic temporal multi-domain correlation engine with explicit window, clock-skew tolerance, signal thresholds and confidence policy.
- Tenant isolation, duplicate-event suppression and out-of-order normalization in correlation processing.
- `TF-CORR-001` generic multi-domain correlation detection rule.
- `TF-GNSS-CORR-001` GNSS disruption ↔ network fade/C2 correlation pack.
- Evidence hashing and evidence-custody records for correlated detections.
- Synthetic governed validation corpus and reproducible correlation benchmark.
- Adversarial tests for missing telemetry, temporal separation, weak signals, duplicate/out-of-order events, uncertainty and cross-tenant input.
- Correlation evidence visualization in the reference dashboard and public web repository.
- Phase 1 architecture and validation-boundary documentation.

### Evidence boundary
- Phase 1 is **implemented — repository validated; production field validation not established**.
