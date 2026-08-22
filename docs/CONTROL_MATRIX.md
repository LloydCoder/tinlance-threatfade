# Enterprise Control Matrix

| Domain | Control | Evidence in repository | Deployment responsibility |
|---|---|---|---|
| Govern | Security ownership / disclosure | `SECURITY.md` | Owner |
| Govern | Security architecture | `docs/SECURITY_ARCHITECTURE.md` | Owner + reviewers |
| Govern | Threat model | `docs/THREAT_MODEL.md` | Owner + reviewers |
| Govern | ASVS 5.0 verification baseline | `docs/ASVS_5.0_MATRIX.md` | Shared |
| Govern | Risk register | `docs/THREAT_MODEL.md` | Owner + reviewers |
| Govern | NIST CSF 2.0 alignment | `docs/ASVS_5.0_MATRIX.md` | Owner |
| Protect | Input validation and bounded uploads | `core/api_security.py` | Shared |
| Protect | Rate limiting | `core/api_security.py` | Shared |
| Protect | Security headers / request IDs | API middleware | Shared |
| Protect | Secret handling | `.env.example`, deployment docs | Operator |
| Detect | Detection-as-code | `core/detection_pack.py` | Shared |
| Detect | Benchmarking | `benchmarks/` | Shared |
| Detect | Adversarial tests | `tests/` | Shared |
| Detect | ATT&CK mapping | `mitre/` | Shared |
| Respond | SIEM/interoperability | `core/interoperability.py`, `core/siem_exporter.py` | Operator |
| Recover | Backup/restore policy | enterprise readiness docs | Operator |
| Supply chain | CI/SCA/SBOM | GitHub Actions | Shared |
| Runtime | Non-root container | `Dockerfile` | Operator |
| Runtime | Readiness/health checks | `/health`, `/ready` | Shared |
| Governance | ADR process | `docs/adr/` | Maintainers |
| Verification | Group 1 architecture gate | `scripts/validate_security_architecture.py` | Shared |

This matrix is a readiness map, not a certification. SOC 2, ISO 27001, NIST CSF, or regulatory compliance requires organization-level processes, evidence, contracts, and independent assessment beyond source code.
