# Phase 20 — Independent Assurance

## Status

**GREEN — preparation infrastructure ready. Independent execution is NOT completed and is NOT claimed.**

Phase 20 converts the evidence boundaries established through Phase 16.5 and the enterprise assurance material in Phase 19 into a controlled package that can be executed by qualified independent evaluators.

## Evidence state model

| State | Meaning |
|---|---|
| Implemented | Capability exists in the repository. |
| Internally tested | Automated or manual project tests exercise it. |
| Internally validated | A governed project evaluation produced reproducible evidence. |
| Externally validated | An external evaluator reproduced the evaluation. |
| Independently audited | An independent assessor evaluated the defined assurance scope. |
| Certified | A formal certification or attestation exists and is in force. |

Repository preparation cannot promote a claim into external validation, independent audit or certification.

## Implemented preparation infrastructure

### 20.1 Independent detection validation

`docs/evaluation/INDEPENDENT_VALIDATION_PACKAGE.md` defines the evaluator inputs, outputs, independence controls, frozen artifacts, blind-set rules, evidence chain and publication gate.

### 20.2 Independent security testing

`docs/evaluation/PENTEST_SCOPE.md` defines the target surfaces, required security tests, rules of engagement, deliverables and methodology references for a qualified third-party penetration test.

The scope is informed by NIST SP 800-115 and the current OWASP Web Security Testing Guide.

### 20.3 Benchmark expansion

`docs/evaluation/SCALE_BENCHMARK_PROTOCOL.md` defines reproducible throughput, latency, resource, concurrency and failure-recovery measurement requirements without inventing results.

### 20.4 Purple-team validation

`docs/evaluation/PURPLE_TEAM_PROTOCOL.md` defines controlled adversarial scenario families, freeze/blind execution, ATT&CK-oriented behavior mapping and evidence requirements.

### 20.5 Evidence manifest

`docs/evaluation/PHASE_20_ASSURANCE_MANIFEST.json` is the fail-closed claim/evidence registry. External validation and certification remain explicitly incomplete until evidence is attached.

### 20.6 Automated gate

`scripts/validate_phase20_assurance.py` and `.github/workflows/phase20-assurance.yml` prevent repository preparation from silently promoting unvalidated claims.

## External execution package

An independent evaluator should receive:

1. frozen ThreatFade release
2. detector/detection-pack digests
3. corpus and blind-set manifests
4. reproducible environment definition
5. evaluation commands and schemas
6. rules of engagement for security testing
7. result integrity/signing instructions
8. deviation process

The evaluator should return a signed report with the required metrics, environment information, artifact digests, scenario-level results, limitations and deviations.

## Research and assurance basis

The methodology uses:

- NIST SP 800-115 for technical security testing and assessment planning.
- NIST SP 800-55 Volumes 1 and 2 for measurement selection, documentation, analysis and uncertainty.
- OWASP Web Security Testing Guide for structured web/API security testing.
- MITRE ATT&CK adversary-emulation material for behavior-oriented purple-team planning.

## What is deliberately NOT claimed

- independent detection validation
- independent penetration test
- independent security audit
- SOC 2/ISO 27001 or other certification
- independently reproduced customer-scale performance
- external benchmark superiority

## Gate to completed independent assurance

Phase 20 preparation is ready for external execution when CI is green and the package is frozen. Actual independent assurance remains an evidence-driven post-execution state change.
