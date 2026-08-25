# Changelog

All notable changes to ThreatFade will be documented in this file.

## Unreleased — Phase 7 Performance and Scale

### Added
- Reproducible sustained software-data-plane benchmark covering canonical event serialization, bounded session reconstruction and the existing detection pipeline.
- 10K, 100K and 500K target-throughput CI matrix.
- Benchmark reporting for throughput, target-achievement ratio, p50/p95/p99 processing latency, RSS and pipeline depth.
- Explicit benchmark methodology separating synthetic software-data-plane throughput from platform capture/NIC packet-loss measurements.
- Performance engineering rule requiring measured hotspot evidence before Python vectorization, multiprocessing, native extensions, Rust, eBPF or GPU work.

### Evidence boundary
- Phase 7 does not claim 1M+ packets/sec.
- Synthetic benchmark throughput is not equivalent to NIC capture throughput and cannot establish packet-loss behavior.
- Production capacity must be benchmarked on the target sensor hardware, capture adapter, workload mix and deployment configuration.

## Unreleased — Phase 6 Enterprise Security Integrations

### Added
- Canonical `IntegrationEvent` model carrying tenant, detection, session, asset, evidence, provenance, severity and confidence context.
- One shared `IntegrationTransport` for authentication, TLS validation, bounded timeout, retry/backoff, idempotency, delivery audit and dead-letter handling.
- Thin destination adapters for Elastic, Microsoft Sentinel, IBM QRadar, Graylog, Wazuh, MISP, OpenCTI, TheHive and vendor-neutral SOAR webhooks.
- Credential-provider boundary supporting bearer, API-key, basic, HMAC-SHA256 and client-certificate authentication without persisting secrets.
- Deterministic tenant/event idempotency keys and duplicate acknowledgement handling.
- Phase 6 integration contract tests covering adapter registration, payload generation, retries, failures, duplicate delivery, TLS policy, tenant propagation and credential non-disclosure.
- `docs/ENTERPRISE_INTEGRATIONS.md` defining the normalized integration architecture and deployment validation boundaries.

### Evidence boundary
- Phase 6 proves the normalized implementation and repository-level transport behavior; it does not claim live connectivity, certification or production interoperability testing against every third-party deployment.
- Microsoft Sentinel deployments should use the supported Logs Ingestion API/data-connector architecture rather than the deprecated HTTP Data Collector API.
- OpenCTI GraphQL schema/version mapping, Wazuh ingestion configuration, TheHive routes and QRadar receiver configuration remain target-deployment contracts.
- FusionOps remains an external integration boundary and is not replaced or weakened by the new adapter framework.

## Unreleased — Phase 5 Environment Profiles and Adaptive Baselines

### Added
- Tenant-scoped `EnvironmentProfile` schema v1.1 with expected protocols, ports, destinations, entropy and periodicity baselines, sensitivity thresholds, integrations, retention and deployment constraints.
- Persistent `environment_profiles` and `environment_profile_audit` storage with PostgreSQL row-level tenant isolation.
- Immutable monotonically versioned profile lifecycle with explicit activation and audited rollback.
- Profile validation with bounded fields, duplicate/conflict rejection and deterministic SHA-256 profile digests.
- Separate `ObservationContext` and `AuthorizationAssessment` models so observed telemetry is never conflated with authorized behavior.
- Hostile-condition tests for malformed profiles, profile version collisions/skips, unauthorized changes, active-profile conflicts, rollback and cross-tenant access.

### Evidence boundary
- Environment profiles are configuration/context, not maliciousness verdicts.
- An authorization mismatch is never sufficient evidence of malicious behavior.
- Phase 5 does not implement EMCON, military classification, clearance levels or policy-as-verdict logic.
- Structural validation does not prove profile accuracy or freshness; deployment-specific validation remains required.

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
- Phase 4 is implemented and repository validated. The benchmark does not claim 1M+ packets/sec or NIC line rate.
- Windows service installation, Npcap deployment and enterprise PKI enrollment remain deployment-validation boundaries.

## Unreleased — Phase 3 Production SOC / Analyst Platform

### Added
- Tenant-scoped detection inbox, investigation workspace, evidence timeline, entity/session explorer, case linking and analyst disposition workflow.
- Server-side web-to-engine analyst API boundary and tenant-isolated durable workflow records.

### Evidence boundary
- Phase 3 is repository validated; production identity-provider and live FusionOps handoff validation remain external.

## Unreleased — Phase 2 Resilient Transport and Offline Evidence

### Added
- Bounded SQLite-backed store-and-forward queue, bandwidth-aware batching, monotonic sequencing and idempotent replay.
- Signed ThreatFade Evidence Package v1, offline verification, persistent signing trust and hostile-condition validation.

### Evidence boundary
- Cryptographic verification proves signed-byte integrity/authenticity; it does not prove sensor truth, maliciousness or causal attribution.

## Unreleased — Phase 1 Multi-Domain Fade Correlation

### Added
- Reusable temporal multi-domain correlation, GNSS ↔ network fade detection pack, evidence custody and dashboard visualization.

### Evidence boundary
- Correlation is observed correlation, not causal attribution; production field validation remains external.
