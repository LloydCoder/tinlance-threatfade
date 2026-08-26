# ThreatFade Phase 16 Research Program

This directory defines the reproducible research boundary used by the ThreatFade web research program.

## Flagship study

**Behavioral Fade Detection Reproducibility Study v1**

Research question:

> Can a behavioral fade detector distinguish documented fade scenarios from a benign transient fade under a controlled, reproducible evaluation protocol without treating any single feature as a maliciousness verdict?

The study is a protocol and artifact registry until an execution report is generated. This repository change does **not** publish benchmark results.

## Evidence classes

- `synthetic`: deterministic fixtures and generated scenarios. Useful for regression and reproducibility, not real-world generalization.
- `project_validation`: repository-backed evaluation under documented conditions.
- `independent`: independently collected/labeled data or third-party evaluation.
- `experimental`: candidate methods not promoted to production.
- `planned`: future evidence requiring collection or external review.

## Reproduction boundary

The current reproducible baseline uses:

- `datasets/fixtures/ground_truth_v1.jsonl`
- `benchmarks/phase7_benchmark.py` for software data-plane performance measurement
- `benchmarks/detection_science_v2.py` and the existing detection evaluation tooling for detection-science experiments
- existing deterministic signal scenarios in `agents/signal_generator.py`
- existing tests and validation scripts as correctness gates

The benchmark protocol records dataset version/digest, engine commit, Python/runtime versions, configuration, split, scenario counts, threshold configuration, metrics, latency/resource measurements where relevant, and limitations.

## Metrics

Detection evaluation should report, where labels permit:

- TP, TN, FP, FN
- precision
- recall / sensitivity
- specificity
- F1
- false-positive rate
- false-negative rate
- PR-AUC/ROC-AUC only when the score distribution and labels support those calculations
- calibration metrics when probabilistic confidence is evaluated

Performance evaluation is separate and reports throughput, p50/p95/p99 latency, RSS, queue depth and accepted/dropped events as applicable. It must not be presented as packets/sec at the NIC unless capture-host evidence exists.

## Limitations

The current ground-truth fixture is synthetic and intentionally small. It cannot establish production detection accuracy or generalization. Real-PCAP, independently labeled corpora, adversarial adaptation, environmental diversity and third-party evaluation remain separate evidence requirements.

## Challenge

The public Detection Challenge uses the same evidence discipline: participants receive versioned, non-sensitive challenge artifacts and submit reproducible predictions or detector outputs. Leaderboards must remain empty until a verified submission is actually evaluated. No fabricated scores are permitted.
