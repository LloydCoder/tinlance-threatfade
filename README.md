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

Production OIDC settings:

```text
THREATFADE_OIDC_ISSUER
THREATFADE_OIDC_AUDIENCE
THREATFADE_OIDC_JWKS_URL   # optional; issuer discovery is used when omitted
```

Production tokens must contain `sub`, `exp`, `iat` and a tenant claim using the documented tenant naming convention. Exact redirect URI registration, TLS, secure token handling and PKCE where applicable remain deployment requirements.

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

ThreatFade supports:

- JSON.
- Splunk HEC.
- CEF.
- CSV.
- Sigma-compatible output.
- STIX 2.1-compatible bundles.
- MITRE ATT&CK mapping.
- FusionOps integration.

The goal is not to replace an enterprise SIEM/SOAR. ThreatFade provides a specialized detection/evidence layer that can feed existing security operations systems.

## Benchmarking and validation

Run:

```bash
python benchmarks/benchmark.py
python benchmarks/correlation_validation.py
python scripts/validate_phase2.py
```

The deterministic benchmark is intentionally separate from real-PCAP validation. The repository records author-confirmed validation against Merlin QUIC C2, Cobalt Strike and IcedID and the documented 0% false-positive baseline across five normal traffic patterns and 100 test runs. These are project validation results—not universal accuracy guarantees.

Phase 1 adds a governed synthetic correlation corpus covering positive/negative temporal relationships, weak signals, missing telemetry and ordering/duplication conditions. This validates deterministic implementation behavior; it does **not** establish field false-positive/false-negative rates, GNSS jamming/spoofing classification accuracy, causal attribution or customer-scale performance.

Phase 2 adds deterministic hostile-condition validation for bounded local storage, replay/idempotency, signature verification, key revocation and portable offline verification. Repository validation is not a substitute for production deployment soak testing or independent key-management assurance.

Independent labeled corpora, third-party penetration testing, purple-team exercises and customer-scale load testing are external assurance activities and are not represented as completed merely because repository tests pass.

## Observability and reliability

ThreatFade includes optional OpenTelemetry instrumentation, request IDs, health/readiness endpoints, structured audit events, alert deduplication, streaming/parallel processing components and operational export paths.

Production teams should measure:

- API availability.
- Detection p50/p95/p99 latency.
- Throughput.
- Error rate.
- Alert volume.
- False-positive budget.
- Resource utilization.
- Queue depth/backpressure where a distributed deployment is used.
- Offline queue depth, bytes used, retention/eviction and replay backlog where offline transport is deployed.
- Backup/restore results.
- Recovery time and recovery point performance.
- Correlation latency, clock-skew tolerance and missing-domain rates where multi-domain correlation is deployed.

The readiness endpoint exposes configured SLO targets. Targets are **targets**, not guarantees; production evidence is required before publishing measured SLOs.

## Deployment

Reference local/production Compose assets are provided in the repository. A typical production boundary is:

```bash
export POSTGRES_PASSWORD='use-a-secret-manager'
export THREATFADE_OIDC_ISSUER='https://idp.example.com/realms/security'
export THREATFADE_OIDC_AUDIENCE='threatfade-api'
export THREATFADE_ALLOWED_ORIGINS='https://console.example.com'
docker compose up --build
```

For enterprise Kubernetes deployments, use the hardened container and Kubernetes assets, externalize secrets, configure TLS at the edge, use persistent storage, and connect application telemetry to the organization's observability backend. If offline transport is enabled, its SQLite queue and replay/trust stores must be on persistent, access-controlled storage with capacity monitoring.

## Governance and assurance boundary

The engineering baseline is informed by OWASP ASVS 5.0 and NIST CSF 2.0. Repository documentation includes a threat model, control matrix, architecture decisions, disclosure process and enterprise implementation boundary.

The following cannot be honestly self-certified by a repository:

- SOC 2 / ISO 27001 certification.
- Independent penetration testing.
- Independent detection validation.
- Contractual SLAs.
- Customer-scale performance guarantees.
- Data-residency commitments.
- Organization-level incident-response obligations.
- Causal attribution of correlated GNSS/network events.
- Field-validated GNSS jamming/spoofing classification.
- Production PKI/HSM assurance for offline evidence signing.

Those require organizational controls, evidence, contracts and/or independent assessment.

## Testing

```bash
python -m compileall -q .
pytest -q
python benchmarks/benchmark.py
python benchmarks/correlation_validation.py
python scripts/validate_phase2.py
python -c "from core.detection_pack import detection_pack, validate_pack; validate_pack(detection_pack()); print('detection pack: OK')"
python scripts/enterprise_smoke.py
```

GitHub Actions validates Python 3.11 and 3.12, compilation, the complete test suite, benchmark, detection-pack validation, enterprise/dashboard smoke checks and production-container build. The security workflow covers dependency auditing, CodeQL and secret scanning. The Phase 2 workflow adds bounded offline transport, replay, signing and air-gap validation.

## Repository structure

```text
ThreatFade/
├── agents/             # signal-generation and endpoint components
├── api.py              # FastAPI control/data-plane boundary
├── benchmarks/         # reproducible validation
├── core/               # detection, correlation, security, storage, evidence and observability
├── dashboard/          # ThreatFade Dashboard / analyst console
├── docs/               # enterprise, threat-model and architecture documentation
├── integrations/       # external operational integrations
├── mitre/              # ATT&CK mapping
├── reports/            # generated validation/interoperability outputs
├── scripts/             # enterprise smoke and operational tooling
├── tests/               # unit/integration/security coverage
├── validation/          # governed validation corpora
├── Dockerfile
├── docker-compose.yml
└── .github/workflows/   # CI and security gates
```

## Release truth

The current release baseline remains **v0.7.0**. Groups 1–11 established the enterprise-hardening and canonical detection data-plane baseline. Group 12 adds reusable multi-domain temporal correlation and the first GNSS/network correlation pack. Group 13 adds resilient offline transport, replay-safe delivery and portable signed evidence packages.

Group 12 is **implemented with repository-level validation**, but it is not represented as independent production validation. In particular, the repository does not claim causal attribution, malicious GNSS interference classification, customer-scale correlation performance or field false-positive/false-negative rates.

Group 13 is **implemented with repository-level validation**. It does not claim production sensor-fleet soak validation, production PKI/HSM assurance or customer-scale reliability evidence.

See `docs/BUILD_STATUS.md` for the evidence-backed implementation and validation boundary.

## License

Apache License 2.0. See `LICENSE`.

**ThreatFade** — Tinlance Limited  
https://tinlance.com/