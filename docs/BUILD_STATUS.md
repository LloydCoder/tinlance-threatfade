# ThreatFade Enterprise Build Status

**Program:** Enterprise Hardening  
**Current release baseline:** v0.8.0-dev  
**Current group:** Group 15 — Production Sensor / Edge Runtime  
**Current build:** Builds 108–114  
**Status:** GROUP 15 GREEN — repository validation complete

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
- Group 11 — Detection Data Plane & Sensor Architecture: ✅ Builds 71–78
- Group 12 — Multi-Domain Fade Correlation: ✅ Builds 83–90
- Group 13 — Resilient Offline Evidence: ✅ Builds 91–97
- Group 14 — Analyst Investigation & Operational Workflow: 🟢 Builds 98–107
- Group 15 — Production Sensor / Edge Runtime: 🟢 Builds 108–114

## Group 15 — Production Sensor / Edge Runtime

| Build | Deliverable | Status |
|---|---|---|
| 108 | Linux sensor runtime | 🟢 |
| 109 | Production live-capture adapter | 🟢 |
| 110 | Windows/Npcap sensor architecture | 🟢 architecture boundary |
| 111 | Offline-first edge runtime | 🟢 |
| 112 | Durable store-and-forward integration | 🟢 |
| 113 | Sensor fleet lifecycle facade | 🟢 |
| 114 | Reproducible sensor-path benchmark | 🟢 repository benchmark |

## Group 15 implementation evidence

- `agents/sensor_runtime.py`
- `agents/live_capture.py`
- `agents/detection_pipeline.py`
- `agents/windows_sensor.py`
- `agents/edge_runtime.py`
- `agents/durable_queue.py`
- `agents/fleet.py`
- `deploy/systemd/threatfade-sensor.service`
- `benchmarks/sensor_runtime.py`
- `tests/test_sensor_runtime.py`
- `tests/test_detection_pipeline.py`

## Architecture and security boundary

The sensor path remains aligned with the Group 11 contract:

`capture → canonical SignalEvent → existing fade engine adapter → bounded durable queue → detection/transport`

The streaming detection adapter reuses `core.fade_engine.detect_fade`; it does not create a parallel detector. Session windows are bounded and keyed by tenant, sensor and flow identity.

Capture privilege is isolated to the platform adapter. Linux deployment uses a dedicated service account and bounds the service to `CAP_NET_RAW`; no `CAP_NET_ADMIN` or broad root execution is required by the reference service. eBPF is not enabled by default because the current ThreatFade packet path does not require kernel-side filtering; it remains an optional future acceleration adapter.

Windows capture is intentionally delegated to Npcap's user/kernel capture architecture rather than a custom driver. The same canonical event contract is used above the capture layer.

The local queue is bounded by bytes, event count and retention. When the control plane is unavailable, capture continues into the durable queue. Overflow is fail-closed for evidence preservation: the queue refuses new events rather than silently evicting unexpired evidence.

Sensor identity is bound to a tenant at enrollment and revoked sensors cannot ingest. Rotation is represented by re-registration under the same tenant with a new fingerprint followed by explicit activation. Production deployment must bind this lifecycle to an authenticated enrollment service; the CLI bootstrap is not a substitute for enterprise PKI.

## Verification evidence

The Phase 4 repository validation gates are green across Python 3.11/3.12 test jobs, PostgreSQL integrity/tenant isolation, Group 10, Group 11, security, supply-chain and production-container validation. The repository benchmark measures canonical-event construction plus durable enqueue and records host metadata; it is not a NIC line-rate benchmark and does not justify a 1M+ packets/sec claim.

Real packet-loss, sustained-duration and hardware-specific capture benchmarks require execution on the target host/NIC with libpcap/AF_PACKET or Npcap. Windows driver installation and enterprise PKI enrollment remain deployment validation boundaries, not unsubstantiated production claims.

## Next planned group

**Group 16 — Production Detection-to-SOC Field Validation / Sensor Fleet Operations.**
