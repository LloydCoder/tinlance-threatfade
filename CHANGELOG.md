# Changelog

All notable changes to ThreatFade will be documented in this file.

## Unreleased — Phase 1 Multi-Domain Fade Correlation

### Added
- Reusable `CorrelationObservation` model over canonical `SignalEvent` data.
- Deterministic temporal multi-domain correlation engine with explicit window, clock-skew tolerance, signal thresholds and confidence policy.
- Tenant isolation, duplicate-event suppression and out-of-order normalization in correlation processing.
- `TF-CORR-001` generic multi-domain correlation detection rule.
- `TF-GNSS-CORR-001` GNSS disruption ↔ network fade/C2 correlation pack.
- Evidence hashing and evidence-custody records for correlated detections.
- Synthetic governed validation corpus and reproducible correlation benchmark.
- Adversarial tests for missing telemetry, temporal separation, weak signals, duplicate/out-of-order events, uncertainty and cross-tenant input.
- Correlation evidence visualization in the reference dashboard and public web repository.
- Phase 1 architecture and validation-boundary documentation.

### Evidence boundary
- Phase 1 is **implemented — not yet production validated**.
- Correlation results are explicitly labeled `observed_correlation` and `causal_attribution=not_established`.
- Synthetic validation does not establish field false-positive/false-negative rates, GNSS jamming/spoofing classification accuracy, causality or customer-scale performance.

## [0.7.0] – 2026-08-22

### Secure Deployment, Supply Chain & Production Operations

#### Added
- Digest-pinned Python base container image with OCI source metadata.
- Build-context exclusions for source control metadata, local environments, recovery artifacts and temporary files.
- Mandatory SHA-pinned GitHub Actions across CI/security/supply-chain workflows.
- SPDX SBOM generation and vulnerability scanning for the production container.
- Trivy Dockerfile/Kubernetes configuration scanning.
- Main-branch GHCR publication using commit-derived immutable image tags.
- OIDC-backed GitHub artifact attestations for SLSA build provenance.
- Signed SPDX SBOM attestations attached to the released image digest.
- Kubernetes dedicated service account with token automount disabled.
- Kubernetes read-only root filesystem, dropped capabilities, non-root execution, seccomp and no privilege escalation.
- Isolated writable `emptyDir` mounts for application report/tmp paths.
- Kubernetes NetworkPolicy baseline and production image pull policy.
- Fail-closed production digest renderer requiring `@sha256:<64-hex>` image references.
- Supply-chain architecture acceptance validator integrated into core CI.
- Secure deployment and release-gate documentation.

#### Operational notes
- Pull requests build and scan without package-write or attestation privileges.
- Main-branch publication requires the complete test/security/supply-chain pipeline to pass first.
- Production promotion must use the rendered digest-pinned manifest; the generic deployment manifest is not the final release artifact.
- External secret-management integration remains an infrastructure responsibility and must bind runtime credentials through Kubernetes Secrets or an approved external-secrets implementation.

## [0.6.0] – 2026-08-22

### Disaster Recovery, Backup & Operational Continuity

#### Added
- Portable PostgreSQL custom-format backup generator with SHA-256 integrity manifest.
- Credential-safe PostgreSQL command construction using `PGPASSWORD` instead of database credentials in command-line arguments.
- Backup catalog verification using `pg_restore --list`.
- Isolated restore drill verifying Alembic migration state, required enterprise tables and forced PostgreSQL RLS.
- Disaster-recovery architecture acceptance gate.
- CI-integrated backup creation, artifact verification and isolated restore verification against PostgreSQL 16.
- Recovery runbook defining RPO/RTO targets, backup tiers, restore procedure, integrity checks and infrastructure boundaries.

#### Operational notes
- Production low-RPO recovery is expected to use provider-native PostgreSQL PITR/WAL archiving; the repository's logical dump is a complementary portable recovery mechanism.
- CI recovery artifacts are ephemeral and are never committed to the repository.
- RPO/RTO values are engineering targets, not contractual guarantees.

## [0.5.0] – 2026-08-22
