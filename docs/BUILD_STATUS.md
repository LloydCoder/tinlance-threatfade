# ThreatFade Enterprise Build Status

**Program:** Enterprise Hardening  
**Current release baseline:** v0.4.0  
**Current group:** Group 4 — Data Integrity, Evidence & Audit  
**Current build:** Build 33  
**Status:** IMPLEMENTATION COMPLETE — final hosted CI/security verification gate

## Group 1 — Security Architecture & Threat Model

| Build | Deliverable | Status |
|---|---|---|
| 15 | Security architecture, trust boundaries, assets, principals, invariants | ✅ Complete |
| 16 | Threat model v2, STRIDE analysis, DFD, abuse cases, risk register | ✅ Complete |
| 17 | ASVS 5.0 baseline matrix, NIST CSF 2.0 mapping, architecture validation gate | ✅ Complete |

## Group 2 — Detection Science & Validation

| Build | Deliverable | Status |
|---|---|---|
| 18 | Repeated-seed evaluation engine, confusion metrics, bootstrap intervals, scenario reporting and latency metrics | ✅ Complete |
| 19 | Ground-truth corpus schema, provenance and cross-split leakage validation | ✅ Complete |
| 20 | Score ranking, AUROC/AUPRC, Brier/ECE calibration metrics | ✅ Complete |
| 21 | Corpus validation CI gate and auditable synthetic ground-truth fixture | ✅ Complete |
| 22 | Reproducible tuning-set threshold calibration with constrained FPR option | ✅ Complete |
| 23 | Deterministic adversarial perturbation harness and group CI gate | ✅ Complete |

**Group 2 gate:** implementation complete. Synthetic results remain regression evidence only; real-world and independent validation are explicitly deferred to later assurance work.

## Group 3 — Detection Pack Platform

| Build | Deliverable | Status |
|---|---|---|
| 24 | Immutable detection-pack identity, canonical content hashing and lifecycle promotion primitives | ✅ Complete |
| 25 | Pack manifest/schema hardening and semantic compatibility validation | ✅ Complete |
| 26 | Pack Ed25519 signing/verification and in-toto/SLSA-shaped provenance | ✅ Complete |
| 27 | Controlled canary/production lifecycle, rollback and pack regression gate | ✅ Complete |

### Group 3 evidence

- `core/detection_pack_registry.py`
- `core/detection_pack_platform.py`
- `tests/test_detection_pack_registry.py`
- `tests/test_detection_pack_platform.py`

The pack platform uses canonical SHA-256 identity, explicit semantic-version compatibility, immutable Ed25519 signatures, provenance subjects bound to the pack digest, and controlled lifecycle transitions. Provenance uses the SLSA v1 predicate URI without claiming external SLSA certification.

## Group 4 — Data Integrity, Evidence & Audit

| Build | Deliverable | Status |
|---|---|---|
| 28 | Alembic/PostgreSQL production schema and migration boundary | ✅ Complete |
| 29 | PostgreSQL row-level tenant isolation and application tenant context | ✅ Complete |
| 30 | Append-only cryptographically chained audit with export and correlation IDs | ✅ Complete |
| 31 | Evidence hashing, custody chain and integrity manifests | ✅ Complete |
| 32 | Detection/input/rule-pack/engine/model/config provenance and investigation timeline | ✅ Complete |
| 33 | Retention policy/legal hold primitives, regression gates and enterprise integrity verification | ✅ Complete |

### Group 4 evidence

- `core/storage.py`
- `core/integrity.py`
- `core/audit.py`
- `core/evidence.py`
- `alembic/`
- `scripts/validate_postgres_integrity.py`
- `tests/test_integrity.py`

Production PostgreSQL schema installation is migration-controlled. Tenant-scoped tables have PostgreSQL RLS policies with forced RLS, while application functions retain explicit tenant predicates and set the transaction-local tenant context. Audit events are append-oriented and cryptographically chained. Evidence records bind content SHA-256 hashes into a custody chain and exportable manifest. Detection provenance binds input, rule-pack, engine, model and configuration digests under a correlation ID. Investigation timeline, retention policy and legal-hold primitives are persisted as first-class records.

## Acceptance gate

- [x] Detection-pack identity is immutable and tamper-evident.
- [x] Pack schema and semantic engine compatibility are validated.
- [x] Pack signatures are verifiable and tamper detection is tested.
- [x] Pack provenance is bound to immutable content identity.
- [x] Lifecycle promotion and controlled rollback are explicit.
- [x] PostgreSQL schema installation is migration-controlled.
- [x] Tenant isolation is enforced at the PostgreSQL RLS boundary.
- [x] Audit events are cryptographically chained and exportable.
- [x] Evidence has content hashes and chain-of-custody hashes.
- [x] Detection provenance links inputs, rules, engine, model and configuration.
- [x] Correlation IDs connect detection, evidence, provenance and timeline records.
- [x] Retention policy and legal-hold primitives exist.
- [x] Python 3.11/3.12 CI, security gates and PostgreSQL integrity gate must remain green.

## Verification boundary

Repository tests and CI gates demonstrate implementation and regression evidence. They do not constitute SOC 2/ISO certification, independent penetration testing, independent detection validation, contractual SLAs, or customer-scale performance guarantees.

## Next

**Group 5 — Reliability, Observability & Resilience.**
