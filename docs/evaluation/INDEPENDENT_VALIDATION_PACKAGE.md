# ThreatFade Independent Validation Package

## Status

**Preparation infrastructure ready; independent execution not completed and not claimed.**

This package defines what an external evaluator receives. It is deliberately separate from the detector development environment.

## Assurance boundary

ThreatFade distinguishes the following evidence states:

- **Implemented** — capability exists in the repository.
- **Internally tested** — automated/manual project tests exercise the capability.
- **Internally validated** — a governed project evaluation produced reproducible evidence.
- **Externally validated** — an external evaluator reproduced the defined evaluation.
- **Independently audited** — an independent assessor evaluated the stated assurance scope.
- **Certified** — a formal certification/attestation exists and is in force.

Phase 20 must never promote an item between these states without the corresponding evidence artifact.

## Required evaluator inputs

1. Immutable corpus manifest and manifest SHA-256.
2. Sample references/hashes and legal handling instructions.
3. Frozen ThreatFade release and detection-pack versions.
4. Reproducible environment definition.
5. Evaluation command and schema.
6. Predefined holdout/blind split rules.
7. Result-signing and artifact-integrity instructions.
8. Rules of engagement for security testing where applicable.

## Required evaluator outputs

- evaluator identity/reference
- environment and tool versions
- corpus manifest digest
- detector artifact digest
- test-set digest
- confusion matrix
- precision/recall/F1
- FPR/FNR
- AUROC/AUPRC when scores are available
- calibration metrics where probabilities are claimed
- latency/throughput measurements
- per-scenario results
- limitations and deviations
- signed final report

## Independence requirements

The evaluator must control the blind labels/samples during execution. ThreatFade development personnel must not alter detector thresholds, labels or corpus membership after the blind set is frozen. Any deviation invalidates the run until independently reviewed.

## Evidence chain

```text
corpus manifest
    -> manifest digest
    -> frozen detector artifact
    -> isolated evaluation run
    -> result artifact
    -> result digest
    -> evaluator report
```

A successful internal benchmark is **not** an independent validation. This distinction is mandatory in customer, investor and regulatory communications.

## Recommended evaluation protocol

Run first on a representative holdout set, then on a separately governed blind set. Include benign background traffic, multiple protocol families, partial capture conditions and controlled adversarial transformations. Report confidence intervals and denominator/support for every headline rate.

No accuracy or false-positive claim should be published without its dataset definition, prevalence, threshold, confidence interval and evaluation conditions.

## Security testing preparation

For web/API security assurance, the external test should be scoped using the ThreatFade penetration-test scope in `docs/evaluation/PENTEST_SCOPE.md`, with the OWASP Web Security Testing Guide and NIST SP 800-115 as reference methodologies. For adversarial detection validation, use `docs/evaluation/PURPLE_TEAM_PROTOCOL.md`. For scale assurance, use `docs/evaluation/SCALE_BENCHMARK_PROTOCOL.md`.

## Publication gate

Before publishing any independent-assurance claim, attach the signed evaluator report and artifact digests to the evidence manifest. If those artifacts are absent, the public status remains **not independently validated**.
