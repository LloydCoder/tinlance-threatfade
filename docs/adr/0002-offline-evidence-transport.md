# ADR 0002 — Offline Evidence Transport Boundary

## Status
Accepted for Phase 2.

## Context

Group 11 intentionally made the detection data plane transport-agnostic and bounded. Sensors must remain useful when a control plane is unavailable, but adding a durable queue must not weaken the existing in-memory backpressure contract or tenant isolation.

## Decision

Add a local SQLite-backed store-and-forward layer after canonical `SignalEvent` creation. The layer:

1. enforces hard byte/event/retention bounds;
2. uses priority-aware eviction with explicit exhaustion;
3. assigns monotonic sensor-local sequence numbers;
4. signs batches with Ed25519;
5. persists server-side replay/idempotency state;
6. verifies tenant and sensor identity before acceptance;
7. provides a portable evidence package for offline verification;
8. keeps key trust, rotation and revocation state explicit.

The control plane remains responsible for durable enterprise persistence and transport policy. The queue does not become a second detection database or capture implementation.

## Rejected alternatives

### Unbounded filesystem spool
Rejected because disk exhaustion would become an availability and integrity failure.

### In-memory retry only
Rejected because it loses evidence during prolonged control-plane outages.

### Sequence ordering based only on wall-clock time
Rejected because clock skew and manual time changes can reorder events.

### Cloud-only evidence signing
Rejected because the evidence package must remain verifiable across an air gap.

### Reusing release-image Sigstore signatures directly for sensor evidence
Rejected because software artifact provenance and sensor evidence have different trust subjects and lifecycle requirements. The Phase 2 evidence signature can be integrated with organizational PKI/KMS/HSM infrastructure later without changing the package contract.

## Security consequences

Positive:

- bounded disk and memory use;
- deterministic replay semantics;
- explicit tenant isolation;
- tamper detection;
- offline verification;
- auditable key lifecycle.

Residual risks:

- a compromised sensor can sign false observations;
- possession of a valid signing key does not prove sensor truth;
- physical compromise of local storage remains an operational concern;
- production key custody requires deployment-specific KMS/HSM/PKI controls;
- queue eviction can discard low-priority telemetry under sustained overload and must be monitored.

## Compatibility

No Group 11 `SignalEvent` fields are changed. FusionOps contracts remain outside the transport implementation. The protocol is additive and can be introduced without changing existing online ingestion.
