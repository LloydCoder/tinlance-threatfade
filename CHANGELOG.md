# Changelog

All notable changes to ThreatFade will be documented in this file.

## Unreleased — Phase 5 Environment Profiles and Adaptive Baselines

### Added
- Tenant-scoped `EnvironmentProfile` schema with expected protocols, ports, destinations, entropy and periodicity baselines, sensitivity thresholds, integrations, retention and deployment constraints.
- Immutable monotonically versioned profile lifecycle.
- Profile validation with bounded fields and deterministic SHA-256 profile digests.
- Audited activation and rollback with tenant enforcement.
- Explicit separation between observed telemetry and authorized/expected operating context.
- Hostile-condition tests for malformed profiles, profile version collisions/skips, unauthorized changes, rollback and cross-tenant access.

### Evidence boundary
- Environment profiles are configuration/context, not maliciousness verdicts.
- An authorization mismatch is never sufficient evidence of malicious behavior.
- Phase 5 does not implement EMCON, military classification, clearance levels or policy-as-verdict logic.
- Profile accuracy and operational staleness remain deployment responsibilities and require environment-specific validation.

## Unreleased — Phase 4 Production Sensor / Edge Runtime

### Added
- Linux sensor runtime entry point with explicit sensor, tenant, fingerprint and interface configuration.
- Production live-capture adapter using Scapy/libpcap on Linux and the Npcap architecture on Windows.
- Canonical packet-to-`SignalEvent` conversion with bounded snaplen and capture metrics.
- Streaming sensor adapter that reuses the existing `core.fade_engine.detect_fade` implementation rather than creating a parallel detector.
- Offline-first edge runtime that continues local ingestion while the sender/control plane is unavailable.
- SQLite WAL durable store-and-forward queue with bounded bytes, events and retention.
- FIFO sequence ordering, event-ID idempotency and explicit acknowledgement/replay semantics.
- Windows Npcap sensor architecture boundary without introducing a custom kernel driver.
- Sensor fleet lifecycle facade for enrollment, activation, draining, revocation and health reporting.
- Hardened Linux systemd reference service with a dedicated account, `NoNewPrivileges`, filesystem protections and `CAP_NET_RAW` capability bounding.
- Reproducible sensor-path benchmark for canonical event construction and durable enqueue.
- Hostile-condition and tenant-isolation tests for the sensor runtime and streaming detection handoff.

### Evidence boundary
- Phase 4 is **implemented and repository validated**. CI, security, supply-chain, data-plane, database-integrity and benchmark validation gates are green.
- The benchmark does **not** claim 1M+ packets/sec or NIC line rate. Real packet-loss and sustained-duration measurements require target hardware/NIC execution.
- The Linux reference service uses only the capture privilege required by the current adapter. eBPF is intentionally not enabled by default.
- Windows service installation and Npcap deployment remain platform deployment validation rather than a fabricated in-repository installer claim.
- Local bootstrap enrollment is not a substitute for enterprise PKI/device identity infrastructure.

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
- Phase 3 is **implemented — repository validated; production deployment identity-provider and FusionOps handoff validation remain external**.
- Analyst confidence and detection score are assessments, not evidence.
- Investigation correlation does not establish causality or attribution.

## Unreleased — Phase 2 Resilient Transport and Offline Evidence

### Added
- Bounded SQLite-backed store-and-forward queue after the canonical Group 11 `SignalEvent` boundary.
- Explicit event/byte limits and seven-day default retention.
- Bandwidth-aware batch selection with bounded byte budgets and no destructive acknowledgement before transport success.
- Monotonic sensor-local event sequencing and durable replay cursors.
- Idempotent batch IDs and explicit duplicate/replay/gap outcomes.
- Signed batch envelopes using Ed25519.
- Portable ThreatFade Evidence Package v1 with manifest, event/evidence hashes, provenance, sensor/tenant identity and signature metadata.
- Offline package verification without control-plane network access.
- Persistent signing trust store with additive key rotation and explicit revocation.
- Hostile-condition tests and reproducible air-gap validation workflow.

### Evidence boundary
- Phase 2 is **implemented — repository validated; production deployment soak not yet established**.
- Cryptographic verification proves integrity/authenticity of signed bytes; it does not prove sensor truth, maliciousness or causal attribution.

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

### Evidence boundary
- Phase 1 is **implemented — repository validated; production field validation not established**.
