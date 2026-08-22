# ThreatFade Group 10 — Real-World Evidence & Validation

## Engineering status

**Evaluation infrastructure complete. Independent validation remains an external activity.**

Group 10 establishes a governed path from corpus provenance to reproducible internal evaluation and an independent validation package. It does not invent real-world datasets or claim third-party validation that has not occurred.

| Build | Capability | Status |
|---|---|---|
| 63 | Governed threat/evaluation corpus | GREEN |
| 64 | Provenance, integrity and source governance | GREEN |
| 65 | Blind evaluation framework | GREEN |
| 66 | Large deterministic benchmark | GREEN |
| 67 | Environmental/robustness matrix | GREEN |
| 68 | Safe purple-team harness | GREEN |
| 69 | Independent-validation package | GREEN |
| 70 | Validation-report contract | GREEN |

## Evidence boundary

The repository contains synthetic CI fixtures and evaluation machinery. It does **not** contain a fabricated malicious corpus, and it does not treat synthetic results as independent or production validation.

The next evidence step is operational: obtain legally usable, provenance-controlled real traffic corpora and execute the frozen protocol with an independent evaluator.

## Required publication fields

Any future performance report must state:

- dataset provenance and licensing
- sample/flow counts
- malicious/benign prevalence
- split policy and leakage controls
- detector and pack versions
- threshold/calibration policy
- precision, recall, FPR and FNR
- confidence intervals
- latency/throughput conditions
- environmental limitations
- whether the evaluation was internal, customer-observed, or independent

## Claim policy

Do not publish `0% false positive rate`, `production-scale`, `independently validated`, or equivalent claims solely from this repository's synthetic CI benchmarks. Those claims require the corresponding real-world evidence.
