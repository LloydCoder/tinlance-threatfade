# ThreatFade

**Evasion Interception Platform** by Tinlance Limited.

ThreatFade detects moments when adversaries intentionally reduce observable signals—including C2 quieting, gradual LOTL activity reduction and GNSS interference—using entropy analysis, statistical deviation, heuristic detection, confidence scoring, optional ML anomaly detection, ATT&CK mapping, SIEM interoperability and operational integrations.

**Status:** v0.4.0 — enterprise engineering baseline  
**License:** Apache 2.0 (open-core)

## Product standard

ThreatFade is designed as an **evidence-first security operations product**, not a demo dashboard. The architecture separates control-plane concerns (identity, RBAC, tenant policy, configuration and audit) from detection workloads and keeps detection evidence structured so analysts and downstream systems can consume the same record.

The public repository provides enterprise engineering foundations: native OIDC/JWT validation, RBAC, tenant-scoped persistence, audit events, durable PostgreSQL reference deployment, hardened container/Kubernetes assets, readiness/SLO targets, investigation case primitives, SBOM/provenance-backed releases, keyless signing and CI/security gates.

The repository does **not** claim that source code alone constitutes SOC 2/ISO certification, a third-party penetration test, independent detection validation, contractual SLA, or proven customer-scale performance. Those require real deployment evidence and independent or operational assurance. See `docs/ENTERPRISE_IMPLEMENTATION.md`.

## Enterprise analyst console

The dashboard is intentionally organized around the analyst's investigation loop:

**Prioritize → Inspect evidence → Pivot → Disposition → Export / hand off**

The current console provides:

- Operational overview with open-alert, confidence, detection-rate and score metrics.
- Severity filtering and time-window controls.
- Detection activity visualization.
- Priority alert queue with investigation drill-down.
- Structured evidence drawer with confidence, score, z-score, ATT&CK and ML context.
- Detection records table with direct investigation access.
- Safe scenario execution and ML-layer controls.
- API health/version status and operational signal panel.
- Responsive desktop/tablet/mobile layouts.
- Keyboard-friendly drawer dismissal and explicit empty/error states.
- A visual hierarchy designed to reduce cognitive load rather than maximize decorative telemetry.

Dashboard design follows established observability principles: a dashboard should answer a defined operational question, use hierarchical drill-downs, avoid dashboard sprawl, and keep alert-driven navigation focused. urlGrafana dashboard best practiceshttps://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/

The investigation model also follows modern SOC workflows in which an incident aggregates relevant alerts/evidence, exposes entities and a timeline, and allows analysts to pivot without losing investigation context. urlMicrosoft Sentinel incident investigation guidancehttps://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents

## Quick start

```bash
git clone https://github.com/LloydCoder/tinlance-threatfade.git
cd tinlance-threatfade
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python api.py
```

Open the dashboard at `http://localhost:8080/dashboard/` and check readiness:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

For local development, authentication is intentionally permissive. Production requires an OIDC access token containing a tenant claim and appropriate roles.

## Production reference

The production Compose topology uses PostgreSQL for durable tenant-scoped data and persistent audit storage:

```bash
export POSTGRES_PASSWORD='use-a-secret-manager'
export THREATFADE_OIDC_ISSUER='https://idp.example.com/realms/security'
export THREATFADE_OIDC_AUDIENCE='threatfade-api'
export THREATFADE_ALLOWED_ORIGINS='https://console.example.com'
docker compose up --build
```

Production OIDC settings:

```text
THREATFADE_OIDC_ISSUER
THREATFADE_OIDC_AUDIENCE
THREATFADE_OIDC_JWKS_URL   # optional; issuer discovery is used when omitted
```

Tokens must contain `sub`, `exp`, `iat` and a `tenant_id` claim (or the documented Tinlance namespaced equivalent). Supported roles are `viewer`, `analyst`, `api_only`, `admin` and `tenant_admin`.

OAuth/OIDC configuration should follow current OAuth security best practice, including exact redirect URI registration, PKCE where applicable, TLS and secure token handling.

## Detection pipeline

```text
Signal / PCAP
  -> signal extraction
  -> rolling entropy + statistical deviation
  -> detection rules
  -> optional ML anomaly layer
  -> confidence + structured evidence
  -> ATT&CK mapping
  -> JSON / SIEM / Sigma / STIX 2.1 / FusionOps
  -> tenant-scoped durable record + audit event
  -> analyst investigation / case workflow
```

## Capabilities

### Detection

- PCAP/PCAPNG ingestion
- Hybrid encrypted/unencrypted signal extraction
- Rolling Shannon entropy
- Z-score anomaly detection
- C2, LOTL and GNSS fade scenarios
- Optional Isolation Forest layer
- Structured analyst evidence and confidence
- Alert deduplication
- Live network/process monitoring
- AIS/ADS-B/GPS signal-fusion components
- Deterministic benchmark and robustness tests

### Interoperability

- JSON
- Splunk HEC
- CEF
- CSV
- Sigma-compatible output
- STIX 2.1-compatible bundles
- MITRE ATT&CK mapping
- FusionOps integration

### Enterprise identity and tenancy

- OIDC/JWT validation using issuer, audience, JWKS and standard time claims
- Explicit RBAC permission matrix
- Tenant isolation on persisted detections
- Cross-tenant access denied by default
- Tenant-admin and platform-admin separation
- Production fail-closed authentication
- Structured append-only audit events
- PostgreSQL production persistence through SQLAlchemy
- SQLite development persistence
- Investigation case persistence primitives

### Security

- Bounded request and PCAP inputs
- Rate limiting
- Request IDs
- Security headers
- Restrictive CORS
- Finite-number validation
- Safe temporary PCAP handling
- Non-root hardened container
- Dropped Linux capabilities
- `no-new-privileges`
- Kubernetes security context and probes
- Dependabot
- CodeQL
- Gitleaks
- `pip-audit`
- SBOM/provenance generation on releases
- Keyless Sigstore image signing

## Detection packs

Detection rules are versioned with stable IDs, semantic versions, descriptions and ATT&CK mappings. The intended lifecycle is:

**Research → Backtest → Canary → Production → Deprecated**

Current core rules include `TF-C2-001`, `TF-LOTL-001` and `TF-GNSS-001`.

## Benchmarking and validation

Run the deterministic benchmark:

```bash
python benchmarks/benchmark.py
```

The benchmark is separate from real-PCAP validation. The repository records author-confirmed validation against Merlin QUIC C2, Cobalt Strike and IcedID and the documented 0% false-positive baseline across five normal traffic patterns and 100 test runs. These are project validation results, not universal accuracy guarantees.

Independent labeled corpora, third-party penetration testing, purple-team exercises and customer-scale load testing are intentionally treated as external assurance activities rather than fabricated repository claims.

## Observability, reliability and SLOs

ThreatFade includes optional OpenTelemetry instrumentation, structured API request IDs, health/readiness endpoints, alert deduplication, streaming/parallel PCAP processors and operational export paths.

The readiness endpoint exposes configurable SLO targets for API availability, detection latency and RPO/RTO. These are **targets to measure**, not guarantees. Production teams should record p50/p95/p99 latency, throughput, error rate, alert volume, false-positive budget, resource utilization and recovery results under representative load.

## Supply-chain security

Versioned releases build and push an immutable container to GHCR with build provenance/SBOM metadata, GitHub artifact attestation and keyless Sigstore signing. Consumers should verify provenance and signatures before promotion into a production registry.

## Governance and compliance

The engineering baseline is informed by OWASP ASVS 5.0 and NIST CSF 2.0. Repository documentation includes a threat model, control matrix, architecture decisions, disclosure process and enterprise implementation boundary.

SOC 2, ISO 27001, NIST CSF profiles, contractual SLAs, data-processing agreements, data residency commitments and regulatory certifications require organization-level governance, evidence and independent assessment.

## Testing

```bash
python -m compileall -q .
pytest -q
python benchmarks/benchmark.py
python -c "from core.detection_pack import detection_pack, validate_pack; validate_pack(detection_pack()); print('detection pack: OK')"
```

GitHub Actions runs the complete suite on Python 3.11 and 3.12, benchmark, detection-pack validation, enterprise/dashboard smoke checks and production-container build. The security workflow runs dependency auditing, CodeQL and secret scanning.

## Deployment architecture

```text
                         Enterprise IdP
                              |
                         OIDC access token
                              |
Users / SIEM ---> TLS / Edge ---> ThreatFade Control Plane
                                  |  auth / RBAC / tenant policy
                                  |
                                  +---- Detection Data Plane
                                  |       PCAP / live / ML
                                  |
                                  +---- PostgreSQL
                                  |       tenant-scoped state
                                  |
                                  +---- Immutable Audit Sink
                                  |
                                  +---- SIEM / SOAR / FusionOps
                                  |
                                  +---- Analyst Console
```

For HA deployments, run multiple API/worker replicas behind a load balancer, use managed PostgreSQL with backups and tested restore, use a durable queue/object store where workload volume requires it, and configure regional/data-residency controls. The public repository provides the reference components; the production topology must be capacity-tested and operated for the customer's SLOs.

## Documentation

- `docs/ENTERPRISE_IMPLEMENTATION.md` — implemented controls and assurance boundary
- `docs/ENTERPRISE_READINESS.md` — production controls and operational responsibilities
- `docs/THREAT_MODEL.md` — assets, trust boundaries, threats and security invariants
- `docs/CONTROL_MATRIX.md` — enterprise readiness mapping
- `docs/adr/` — architecture decisions
- `SECURITY.md` — responsible disclosure
- `CONTRIBUTING.md` — contribution workflow
- `CHANGELOG.md` — release history

## Limitations

- Detection quality depends on traffic, protocol behavior, signal quality and tuning.
- The public benchmark is deterministic and synthetic.
- Independent validation and real customer load are not represented as completed work unless independently evidenced.
- Volatility 3 support is an optional integration boundary.
- Large PCAP processing is workload-dependent and should be capacity-tested before committing customer SLOs.
- ATT&CK mappings represent implemented project mappings, not complete ATT&CK/STIX coverage.

## Contributing

Detection improvements, regression cases, integrations, benchmarks and documentation are welcome. All changes must preserve the detection evidence contract and pass CI/security checks.

## Related platform

ThreatFade is designed to feed Tinlance's operational security stack, including FusionOps.

**Built by Nwachukwu Chinaemerem (@LloydCoder)**  
**Tinlance Limited**
