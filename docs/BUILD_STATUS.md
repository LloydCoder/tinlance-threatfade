# ThreatFade Enterprise Build Status

**Program:** Enterprise Hardening  
**Current release baseline:** v0.7.0  
**Current group:** Group 7 — Secure Deployment, Supply Chain & Production Operations  
**Current build:** Build 46  
**Status:** IMPLEMENTATION COMPLETE — hosted CI/security verification is the release gate

## Completed groups

- Group 1 — Security Architecture & Threat Model: ✅ Builds 15–17
- Group 2 — Detection Science & Validation: ✅ Builds 18–23
- Group 3 — Detection Pack Platform: ✅ Builds 24–27
- Group 4 — Data Integrity, Evidence & Audit: ✅ Builds 28–33
- Group 5 — Reliability, Observability & Resilience: ✅ Builds 34–37
- Group 6 — Disaster Recovery, Backup & Operational Continuity: ✅ Builds 38–41

## Group 7 — Secure Deployment, Supply Chain & Production Operations

| Build | Deliverable | Status |
|---|---|---|
| 42 | Docker build-context isolation, supply-chain validator, Trivy policy baseline | 🟢 Implemented |
| 43 | Digest-pinned base image, hardened Kubernetes workload identity/filesystem/network posture | 🟢 Implemented |
| 44 | SHA-pinned security actions, SPDX SBOM and vulnerability gates | 🟢 Implemented |
| 45 | GHCR release publication, SLSA provenance and SBOM attestations | 🟢 Implemented |
| 46 | Production digest renderer, CI enforcement and secure deployment documentation | 🟢 Implemented |

### Group 7 evidence

- `Dockerfile`
- `.dockerignore`
- `trivy.yaml`
- `scripts/validate_supply_chain.py`
- `scripts/render_production_manifest.py`
- `.github/workflows/ci.yml`
- `.github/workflows/security.yml`
- `.github/workflows/supply-chain.yml`
- `deploy/kubernetes/deployment.yaml`
- `deploy/kubernetes/production/deployment.template.yaml`
- `docs/SECURE_DEPLOYMENT.md`

### Group 7 acceptance gate

- [x] Docker base image is content-digest pinned.
- [x] Container runs as non-root with dropped capabilities and no privilege escalation.
- [x] OCI source metadata is embedded in the image.
- [x] Build context excludes Git metadata, local environments, recovery artifacts and temporary files.
- [x] All GitHub Actions are referenced by immutable commit SHA.
- [x] CodeQL runs security-extended analysis.
- [x] Gitleaks runs the current Node 24-compatible action release.
- [x] SPDX SBOM is generated for the container.
- [x] SBOM is scanned for high/critical vulnerabilities.
- [x] Dockerfile/Kubernetes configuration is scanned by Trivy.
- [x] Main-branch release image is published under a commit-derived tag.
- [x] Main-branch image receives OIDC-backed SLSA provenance attestation.
- [x] Main-branch image receives an SPDX SBOM attestation.
- [x] Kubernetes service-account token automount is disabled.
- [x] Kubernetes uses non-root, RuntimeDefault seccomp, read-only root filesystem and dropped capabilities.
- [x] Writable application paths are isolated to `emptyDir` volumes.
- [x] NetworkPolicy restricts workload traffic.
- [x] Production rendering refuses mutable image references and requires `@sha256:<64-hex>`.
- [x] Supply-chain validator is mandatory in core CI.
- [x] Pull requests do not receive package-write or attestation privileges.

## Verification boundary

Automated tests and CI demonstrate implementation and regression evidence. They do not constitute independent penetration testing, SOC 2/ISO certification, independent detection validation, contractual SLAs, provider-specific PITR guarantees, or customer-scale performance guarantees.

## Next planned group

**Group 8 — Identity, Access Control & Enterprise Multi-Tenancy.**

Initial focus: authentication boundary review, authorization policy enforcement, tenant context propagation, privileged-operation controls, session/token lifecycle, service-to-service identity, administrative auditability and authorization regression gates.
