# ThreatFade Enterprise Build Status

**Program:** Enterprise Hardening  
**Current release baseline:** v0.4.0  
**Current group:** Group 1 — Security Architecture & Threat Model  
**Current build:** Build 15  
**Status:** GREEN — architecture baseline complete; CI verification required on each change

## Group 1 deliverables

| Build | Deliverable | Status |
|---|---|---|
| 15 | Security architecture, trust boundaries, assets, principals, invariants | ✅ Complete |
| 16 | Threat model v2, STRIDE analysis, DFD, abuse cases, risk register | ✅ Complete |
| 17 | ASVS 5.0 baseline matrix, NIST CSF 2.0 mapping, architecture validation gate | ✅ Complete |

## Evidence

- `docs/SECURITY_ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/ASVS_5.0_MATRIX.md`
- `scripts/validate_security_architecture.py`

## Group 1 acceptance gate

- [x] Security objectives defined.
- [x] Assets and data classifications defined.
- [x] Security principals defined.
- [x] Trust boundaries identified.
- [x] Primary data flows documented.
- [x] STRIDE analysis completed.
- [x] Risk register established with owners/treatments represented as follow-up work.
- [x] Security invariants defined.
- [x] Abuse cases defined for continuous regression testing.
- [x] ASVS 5.0 target established at Level 2 with selected Level 3 controls.
- [x] All 17 ASVS 5.0 chapters mapped for applicability.
- [x] NIST CSF 2.0 alignment documented.
- [x] Deterministic documentation validation added to CI.
- [x] No unsupported certification claim introduced.

## Important boundary

Group 1 establishes the **security specification and verification baseline**. It does not mark future controls as implemented merely because they are documented. High-risk gaps such as PostgreSQL RLS, isolated PCAP workers, tamper-evident audit storage, detection provenance, SSRF egress controls, and disaster-recovery validation remain explicitly tracked for later groups.

## Next group

**Group 2 — Detection Science & Validation**

The next builds will establish the ground-truth/evaluation framework, scenario corpus, statistical evaluation, detection-quality metrics, threshold calibration, regression datasets, and adversarial detection validation.
