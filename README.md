# ThreatFade

**Evasion Interception Platform** by Tinlance Limited.

ThreatFade detects moments when adversaries intentionally reduce observable signals—including C2 quieting, gradual living-off-the-land activity reduction and GNSS interference—using entropy analysis, statistical deviation, heuristic detection, confidence scoring, optional ML anomaly detection, multi-domain temporal correlation, ATT&CK mapping, interoperable exports and operational integrations.

**Status:** v0.7.0 — enterprise engineering baseline  
**License:** Apache 2.0 (open-core)

## What ThreatFade is

ThreatFade is an **evidence-first detection and investigation platform**. Its core thesis is that adversarial activity can become less observable on purpose. Instead of treating a reduction in network or signal activity as automatically benign, ThreatFade models the change, scores the deviation and preserves the evidence required for analyst review.

The product is designed around one operational loop:

**Prioritize → Inspect → Pivot → Disposition → Handoff**

The repository contains the detection engine, API, analyst console, validation/benchmarking framework, interoperability layer and enterprise engineering foundations. It does not claim that source code alone proves SOC 2/ISO certification, third-party penetration testing, independent detection validation, contractual SLAs or customer-scale performance. Those require real operational and independent assurance.

## ThreatFade Dashboard

The repository includes a dedicated **ThreatFade Dashboard** (`dashboard/index.html`) designed as a SOC investigation console rather than a decorative telemetry page.

The current UX includes:

- Priority queue for evidence-backed detections.
- Open-alert, high-confidence, detection-rate, score and platform-health KPIs.
- Recent detection activity visualization.
- Tenant-scoped detection-record table.
- Investigation drawer with structured evidence, confidence, z-outlier, score and ATT&CK context.
- Analyst disposition actions and an explicit investigation workflow.
- Detection simulation controls for C2 quieting, LOTL gradual fade, GNSS jamming, normal-with-fade and mixed scenarios.
- Multi-domain correlation evidence visualization with explicit temporal window and clock-tolerance context.
- Optional ML anomaly layer.
- API health/readiness and operational posture signals.
- Validation posture showing repository evidence separately from external assurance.
- Responsive desktop/tablet/mobile layouts.
- Keyboard-friendly investigation dismissal and explicit loading, empty and degraded states.
- No third-party frontend dependency required for the reference console.

The dashboard follows established observability guidance: operational dashboards should answer defined questions, keep hierarchy clear and support drill-down rather than maximizing the number of charts. OpenTelemetry likewise recommends common semantic conventions so telemetry can be correlated consistently across metrics, logs and traces.

## Quick start

```bash
git clone https://github.com/LloydCoder/tinlance-threatfade.git
cd tinlance-threatfade
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python api.py
```

Open:

```text
http://localhost:8080/dashboard/
```

Health/readiness:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
curl http://localhost:8080/version
```

Local development is intentionally permissive. Production authentication is fail-closed and requires the configured identity boundary.

## Architecture

```text
                           Enterprise IdP
                                │
                           OIDC / JWT
                                │
Users / SIEM ── TLS / Edge ── ThreatFade Control Plane
                                │
                  ┌─────────────┼─────────────┐
                  │             │             │
               Auth/RBAC   Tenant policy   Audit
                  │             │             │
                  └─────────────┼─────────────┘
                                │
                         Detection Data Plane
                                │
                  PCAP / live signals / ML
                                │
                    Detection + Evidence Engine
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
        Domain observations  Temporal         Evidence +
        (network/GNSS/...)  correlation       confidence
              │                 │                 │
              └─────────────────┼─────────────────┘
                                │
                 Local bounded durable queue
                                │
                    Signed batch / replay-safe
                                │
                  Control-plane ingestion
                                │
          Postgres / object-export / telemetry / analyst console
                                │
                JSON / Sigma / STIX / SIEM / FusionOps
```

The implementation separates control-plane concerns from detection workloads. Detection records and audit events are tenant-scoped; production deployments use durable PostgreSQL persistence. The Phase 2 transport layer is intentionally local and bounded: control-plane loss does not require a sensor to discard queued events.

## Detection pipeline

```text
Signal / PCAP
  → signal extraction
  → rolling entropy + statistical deviation
  → domain-specific detection rules
  → canonical SignalEvent
  → bounded durable local queue when transport is unavailable
  → signed batch + replay/idempotency metadata
  → server verification / idempotent ingestion
  → optional temporal multi-domain correlation
  → confidence + structured evidence
  → ATT&CK mapping
  → JSON / SIEM / Sigma / STIX 2.1 / FusionOps
  → tenant-scoped durable record + audit event
  → analyst investigation / disposition
```

Phase 2 also defines the portable **ThreatFade Evidence Package v1** for offline transfer and verification. Cryptographic verification establishes integrity/authenticity of the signed bytes; it does not prove sensor truth, maliciousness or causality.

## Offline evidence

See [`docs/PHASE_2_OFFLINE_EVIDENCE.md`](docs/PHASE_2_OFFLINE_EVIDENCE.md) for the protocol specification, queue limits, replay semantics, key lifecycle, failure behavior and air-gapped verification procedure.

The current repository status intentionally distinguishes **implemented repository behavior** from **production deployment validation**. Real sensor-fleet soak tests, production PKI/HSM integration and customer-scale reliability evidence remain separate validation work.