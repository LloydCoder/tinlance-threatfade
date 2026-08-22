# ThreatFade Enterprise Build Status

**Program:** Enterprise Hardening  
**Current release baseline:** v0.7.0  
**Current group:** Group 11 — Detection Data Plane & Sensor Architecture  
**Current build:** Builds 71–78  
**Status:** GROUP 11 IMPLEMENTED — pending hosted CI/security/supply-chain release gates

## Completed groups

- Group 1 — Security Architecture & Threat Model: ✅ Builds 15–17
- Group 2 — Detection Science & Validation: ✅ Builds 18–23
- Group 3 — Detection Pack Platform: ✅ Builds 24–27
- Group 4 — Data Integrity, Evidence & Audit: ✅ Builds 28–33
- Group 5 — Reliability, Observability & Resilience: ✅ Builds 34–37
- Group 6 — Disaster Recovery, Backup & Operational Continuity: ✅ Builds 38–41
- Group 7 — Secure Deployment, Supply Chain & Production Operations: ✅ Builds 42–46
- Group 8 — Identity, Access Control & Enterprise Multi-Tenancy: ✅ Builds 47–52
- Group 9 — ThreatFade Detection Science 2.0: ✅ Builds 53–62
- Group 10 — Real-World Evidence & Validation Framework: ✅ Builds 63–70

## Group 11 — Detection Data Plane & Sensor Architecture

| Build | Deliverable | Status |
|---|---|---|
| 71 | Canonical immutable signal/packet/flow/session event schema | 🟢 |
| 72 | Transport-agnostic live-sensor ingestion contract | 🟢 |
| 73 | Bounded ingestion queue with explicit backpressure/drop metrics | 🟢 |
| 74 | Tenant-bound sensor identity and lifecycle registry | 🟢 |
| 75 | Active/revoked sensor admission control | 🟢 |
| 76 | Deterministic event canonicalization and SHA-256 integrity digest | 🟢 |
| 77 | Reference endpoint/edge sensor adapter without privileged capture side effects | 🟢 |
| 78 | Group 11 architecture gate and regression suite | 🟢 |

### Group 11 implementation evidence

- `core/data_plane.py`
- `agents/sensor.py`
- `tests/test_data_plane.py`
- `scripts/validate_data_plane.py`
- `.github/workflows/group11-data-plane.yml`
- `docs/GROUP_11_DATA_PLANE.md`

### Group 11 acceptance gate

- [x] A single versioned event schema is used for packet, flow, session and signal observations.
- [x] Events require timezone-aware observation timestamps and bounded metadata.
- [x] Canonical serialization is deterministic and SHA-256 integrity digests are available.
- [x] Ingestion is bounded and exposes accepted/dropped/depth metrics instead of silently growing memory.
- [x] Sensor identities are cryptographically fingerprinted and cannot be rebound across tenants.
- [x] Sensors must be explicitly active before they can emit events.
- [x] Revoked/draining sensors cannot ingest new events.
- [x] The reference adapter is transport-agnostic and does not execute shell commands or open raw sockets.
- [x] Tenant identity is bound to the registered sensor rather than caller-supplied event metadata.
- [x] Data-plane controls have dedicated regression coverage and a fail-closed architecture gate.
- [ ] Hosted CI, security and supply-chain workflows are green for the final PR head.

## Verification boundary

Group 11 introduces the canonical data-plane contract and sensor lifecycle controls. It does **not** claim that a production packet-capture implementation, sensor fleet rollout, or customer-scale throughput has been independently validated. Those remain deployment/performance work and require measured evidence.

## Next planned group

**Group 12 — Production SOC / Analyst Platform.**

Focus: detection inbox, investigation workspace, entity correlation, case-management completion, analyst feedback and end-to-end detection-to-disposition workflow.
