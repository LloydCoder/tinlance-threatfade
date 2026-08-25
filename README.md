# ThreatFade

**Evasion Interception Platform** by Tinlance Limited.

ThreatFade detects moments when adversaries intentionally reduce observable signals—including C2 quieting, gradual living-off-the-land activity reduction and GNSS interference—using entropy analysis, statistical deviation, heuristic detection, confidence scoring, optional ML anomaly detection, multi-domain temporal correlation, ATT&CK mapping, interoperable exports and operational integrations.

**Status:** v0.9.0-dev — enterprise engineering baseline  
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
             Normalized IntegrationEvent / delivery transport
                                │
      Elastic / Sentinel / QRadar / Graylog / Wazuh / CTI / SOAR
                                │
                         FusionOps boundary
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
  → normalized IntegrationEvent
  → shared retry/idempotency/audit transport
  → SIEM / CTI / SOAR / FusionOps destination
  → tenant-scoped durable record + audit event
  → analyst investigation / disposition
```

Multi-domain correlation is implemented as a reusable, domain-agnostic temporal layer. GNSS disruption ↔ network fade/C2 is the first detection-pack implementation. Correlation results are explicitly **observed temporal association**, not causal attribution.

Phase 2 also defines the portable **ThreatFade Evidence Package v1** for offline transfer and verification. Cryptographic verification establishes integrity/authenticity of the signed bytes; it does not prove sensor truth, maliciousness or causality.

## Detection capabilities

- PCAP/PCAPNG ingestion.
- Hybrid encrypted/unencrypted signal extraction.
- Rolling Shannon entropy.
- Z-score anomaly detection.
- C2, LOTL and GNSS fade scenarios.
- Reusable temporal multi-domain correlation.
- GNSS disruption ↔ network fade/C2 correlation detection pack.
- Optional Isolation Forest anomaly layer.
- Structured evidence and confidence scoring.
- Alert deduplication.
- Live network/process monitoring components.
- AIS/ADS-B/GPS signal-fusion components.
- Deterministic benchmarks and robustness tests.
- Bounded durable store-and-forward transport when the control plane is unavailable.
- Signed replay-safe batches and portable offline evidence packages.

### Detection-as-code

Detection packs use stable IDs, semantic versions, descriptions and ATT&CK mappings. The intended lifecycle is:

**Research → Backtest → Canary → Production → Deprecated**

Core rules include `TF-C2-001`, `TF-LOTL-001`, `TF-GNSS-001` and `TF-GNSS-CORR-001`.

## Phase 7 — Performance and Scale

ThreatFade does **not** claim a roadmap-derived 1M+ packets/sec capability. Phase 7 first measures the actual system and only then selects the appropriate optimization technique.

The repository now contains a reproducible sustained software-data-plane benchmark at `benchmarks/phase7_benchmark.py` and CI coverage for 10K, 100K and 500K target events/sec. The harness measures canonical event serialization, the existing bounded session window and detection pipeline, throughput, p50/p95/p99 processing latency, RSS and queue/session depth.

Capture-adapter packet loss, NIC throughput, disk I/O and network I/O require deployment-host benchmarks because synthetic events cannot prove those properties. A 1M events/sec result, if eventually achieved, will be reported only with hardware, software version, workload, duration and loss/latency evidence.

No Rust/native/GPU rewrite is introduced without a measured hotspot and an equivalent regression benchmark. See `benchmarks/README.md` and `docs/BUILD_STATUS.md`.

## Enterprise identity and tenancy

- OIDC/JWT validation with issuer, audience, JWKS and time-claim validation.
- RBAC roles: `viewer`, `analyst`, `api_only`, `admin`, `tenant_admin`.
- Tenant-scoped detection persistence.
- Cross-tenant access denied by default.
- Tenant-admin/platform-admin separation.
- Production fail-closed authentication.
- Append-oriented audit events with request and principal context.
- PostgreSQL production persistence through SQLAlchemy.
- SQLite development persistence.
- Investigation case persistence primitives.
- Offline transport replay state is tenant/sensor scoped and fail-closed on identity mismatch.

## Security and supply chain

The repository includes:

- Bounded request and PCAP inputs.
- Rate limiting.
- Request IDs.
- Restrictive CORS.
- Security headers.
- Finite-number validation.
- Safe temporary PCAP handling.
- Non-root container execution.
- Dropped Linux capabilities.
- `no-new-privileges`.
- Kubernetes security context and health probes.
- Dependabot.
- CodeQL.
- Gitleaks.
- `pip-audit`.
- SBOM generation.
- Build provenance/attestation.
- Keyless Sigstore signing for release images.
- Ed25519 evidence signatures with explicit key validity/revocation state for offline evidence packages.

## Interoperability

### Existing/export-compatible formats

ThreatFade retains its existing JSON, Splunk HEC, CEF, CSV, Sigma-compatible, STIX 2.1-compatible, MITRE ATT&CK and FusionOps boundaries.

### Enterprise integration framework

Phase 6 adds one normalized `IntegrationEvent` and one shared delivery transport with bounded retries, backoff, idempotency, TLS/authentication controls, delivery audit and dead-letter handling. Thin adapters are provided for:

- Elastic / ECS-oriented JSON.
- Microsoft Sentinel Logs Ingestion-shaped records.
- IBM QRadar / CEF.
- Graylog / GELF-shaped JSON.
- Wazuh alert-shaped JSON.
- MISP event payloads.
- OpenCTI GraphQL request envelope.
- TheHive case-compatible payload.
- Vendor-neutral SOAR webhook envelope.

These adapters are **repository-implemented and contract-tested**. They are not claims of live production connectivity or vendor certification. Target platform versions, routes, authentication, schemas and receiver configuration remain deployment-validation responsibilities. See `docs/ENTERPRISE_INTEGRATIONS.md`.

FusionOps remains an external integration boundary and is not replaced by the enterprise adapter framework.
