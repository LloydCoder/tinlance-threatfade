# Changelog

All notable changes to ThreatFade will be documented in this file.

## Unreleased — Phase 2 Resilient Transport and Offline Evidence

### Added
- Bounded SQLite-backed store-and-forward queue after the canonical Group 11 `SignalEvent` boundary.
- Explicit event/byte limits, seven-day default retention and priority-aware eviction.
- Bandwidth-aware batch selection with bounded byte budgets and no destructive acknowledgement before transport success.
- Monotonic sensor-local event sequencing and durable per-tenant/per-sensor replay cursors.
- Idempotent batch IDs and explicit duplicate/replay/gap outcomes.
- Signed batch envelopes using Ed25519.
- Portable ThreatFade Evidence Package v1 with manifest, event/evidence hashes, provenance, sensor/tenant identity and signature metadata.
- Offline package verification without control-plane network access.
- Persistent signing trust store with additive key rotation and explicit revocation.
- Hostile-condition tests for disk/resource bounds, tampering, tenant mismatch, replay, duplicate delivery, sequence gaps, expiry and revocation.
- Reproducible air-gap validation workflow.

### Evidence boundary
- Phase 2 is **implemented — repository validated; production deployment soak not yet established**.
- Cryptographic verification proves integrity/authenticity of signed bytes; it does not prove sensor truth, maliciousness or causal attribution.
- Repository air-gap validation does not substitute for production PKI/HSM/key-management validation.

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
- Phase 1 is **implemented — repository validated; production field validation not established**.
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