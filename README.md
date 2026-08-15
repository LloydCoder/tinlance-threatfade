# ThreatFade

**Evasion Interception Platform** by Tinlance Limited.

ThreatFade detects moments when adversaries intentionally reduce observable signals — including C2 quieting, gradual LOTL activity reduction, and GNSS interference — using entropy analysis, statistical deviation, heuristic detection, confidence scoring, optional ML anomaly detection, ATT&CK mapping, SIEM interoperability, and operational integrations.

**Status:** v0.4.0 — enterprise engineering baseline  
**License:** Apache 2.0 (open-core)

## Quick start

```bash
git clone https://github.com/LloydCoder/tinlance-threatfade.git
cd tinlance-threatfade
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python api.py
```

Check readiness:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

Production container reference:

```bash
export THREATFADE_API_KEY='use-a-secret-manager-in-real-deployments'
docker compose up --build
```

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

### Interoperability

- JSON
- Splunk HEC
- CEF
- CSV
- Sigma-compatible output
- STIX 2.1-compatible bundles
- MITRE ATT&CK mapping
- FusionOps integration

### API security

The API includes bounded input validation, PCAP size limits, rate limiting, request IDs, security headers, readiness checks, finite-number validation, safe upload handling, configurable CORS, and fail-closed production authentication.

Production configuration:

```text
THREATFADE_ENV=production
THREATFADE_API_KEY=<secret-manager-value>
THREATFADE_MAX_PCAP_BYTES=104857600
THREATFADE_MAX_BODY_BYTES=2097152
THREATFADE_RATE_LIMIT=120
THREATFADE_RATE_WINDOW_SECONDS=60
THREATFADE_ALLOWED_ORIGINS=https://your-console.example
```

For enterprise SSO, place the API behind an OIDC identity-aware gateway such as Entra ID, Okta, Auth0, Keycloak, or an equivalent provider. Do not implement tenant identity from an arbitrary client-supplied header.

## Enterprise deployment

Reference assets are provided for hardened deployment:

- Non-root Docker image
- Read-only filesystem / dropped Linux capabilities in the Compose profile
- Kubernetes deployment with probes, resource limits, non-root execution and `seccomp` RuntimeDefault
- Dependabot for Python and GitHub Actions dependencies
- CodeQL analysis
- Gitleaks secret scanning
- Dependency auditing with `pip-audit`
- CODEOWNERS
- Threat model and enterprise control matrix
- Architecture Decision Record process

See [`docs/ENTERPRISE_READINESS.md`](docs/ENTERPRISE_READINESS.md), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), and [`docs/CONTROL_MATRIX.md`](docs/CONTROL_MATRIX.md).

### Enterprise architecture boundary

```text
                    +----------------------+
Users / SIEM -----> | Edge / OIDC / TLS    |
                    +----------+-----------+
                               |
                         Control plane
                     +---------+----------+
                     | ThreatFade API      |
                     | auth / policy       |
                     | rules / exports     |
                     +---------+----------+
                               |
                         Data plane
              +----------------+----------------+
              | detection workers / PCAP / live |
              +----------------+----------------+
                               |
               +---------------+---------------+
               | Postgres | Object Store | Bus |
               +---------------+---------------+
                               |
                     SIEM / SOAR / FusionOps
```

The community repository provides the portable detector and reference deployment. Enterprise operators provide the identity provider, durable storage, queueing, HA, regional controls, backup/restore and customer-specific retention policy.

## Detection evidence

Every detection exposes structured evidence describing why the detector fired, including signal changes, statistical deviation, score and matched rules. This evidence is intended for analyst workflows and downstream automation.

## Detection packs

Detection rules are versioned with stable IDs, semantic versions, descriptions and ATT&CK mappings. The intended lifecycle is:

**Research -> Backtest -> Canary -> Production -> Deprecated**

Current core rules include `TF-C2-001`, `TF-LOTL-001`, and `TF-GNSS-001`.

## Benchmarking and validation

Run the deterministic benchmark:

```bash
python benchmarks/benchmark.py
```

The benchmark is separate from real-PCAP validation. The repository records author-confirmed validation against Merlin QUIC C2, Cobalt Strike and IcedID and the documented 0% false-positive baseline across five normal traffic patterns and 100 test runs. These are project validation results, not universal accuracy guarantees.

The engineering test suite also exercises robustness boundaries such as jitter/noise, sustained fades, constant signals, extreme values, minimum-length inputs and configuration limits.

## Observability and operations

ThreatFade includes optional OpenTelemetry instrumentation, structured API request IDs, health/readiness endpoints, alert deduplication, streaming/parallel PCAP processors and operational export paths.

Recommended production SLOs are documented in `docs/ENTERPRISE_READINESS.md`; they are targets to measure, not guarantees.

## Security and governance

ThreatFade follows a security baseline informed by OWASP ASVS 5.0 and NIST CSF 2.0. The repository includes a maintained threat model, security disclosure process, dependency automation, CodeQL, secret scanning, dependency auditing, secure deployment references and ownership controls.

Compliance claims such as SOC 2 or ISO 27001 require organization-level policies, evidence, contracts and independent assessment; source code alone does not constitute certification.

## Testing

```bash
python -m compileall -q .
pytest -q
python benchmarks/benchmark.py
python -c "from core.detection_pack import detection_pack, validate_pack; validate_pack(detection_pack()); print('detection pack: OK')"
```

GitHub Actions runs the complete suite plus benchmark and detection-pack validation. A separate security workflow performs dependency auditing, CodeQL and secret scanning.

## Limitations

- Real-world detection quality depends on traffic, protocol behavior, signal quality and tuning.
- The public benchmark is deterministic and synthetic; independent labeled corpora and third-party validation remain deployment/customer work.
- Volatility 3 support is an optional integration boundary.
- Large PCAP processing is workload-dependent and should be capacity-tested before committing SLOs.
- ATT&CK mappings represent the implemented project mappings; they are not a claim of complete ATT&CK/STIX coverage.
- Enterprise SSO, HA, multi-region operation, durable customer storage, queue infrastructure and compliance certification are deployment concerns rather than claims that the public repository provides a hosted SaaS control plane.

## Documentation

- `docs/ENTERPRISE_READINESS.md` — production controls and operational responsibilities
- `docs/THREAT_MODEL.md` — assets, trust boundaries, threats and security invariants
- `docs/CONTROL_MATRIX.md` — NIST/enterprise readiness mapping
- `docs/adr/` — architecture decisions
- `SECURITY.md` — responsible disclosure
- `CONTRIBUTING.md` — contribution workflow
- `CHANGELOG.md` — release history

## Contributing

Detection improvements, regression cases, integrations, benchmarks and documentation are welcome. All changes should preserve the detection evidence contract and pass CI/security checks.

## Related platform

ThreatFade is designed to feed Tinlance's operational security stack, including FusionOps.

**Built by Nwachukwu Chinaemerem (@LloydCoder)**  
**Tinlance Limited**
