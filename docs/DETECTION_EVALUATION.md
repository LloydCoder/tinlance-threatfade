# ThreatFade Detection Evaluation Standard

**Group:** 2 — Detection Science & Validation  
**Builds:** 18–23  
**Status:** GREEN baseline complete; real-world validation remains an external evidence requirement

## Purpose

ThreatFade must distinguish a useful detection claim from a benchmark artifact. The evaluation framework separates **ground truth**, **detector output**, **metrics**, **uncertainty**, **score calibration**, **provenance**, and **scenario-level results**.

NIST's current AI measurement guidance emphasizes documented test sets, metrics, methods, uncertainty, representative deployment conditions, repeatable TEVV, and independent assessment where appropriate. urlNIST AI RMF Measurehttps://airc.nist.gov/airmf-resources/airmf/5-sec-core/ MITRE's ATT&CK guidance similarly supports building, testing and refining behavioral analytics using threat-informed adversary behavior. urlMITRE ATT&CK detections and analyticshttps://attack.mitre.org/resources/get-started/detections-and-analytics/

## Implemented capabilities

### Build 18 — Evaluation metrics

`core/evaluation.py` reports:

- TP/FP/TN/FN;
- accuracy;
- precision;
- recall/sensitivity;
- specificity;
- F1;
- false-positive rate;
- false-negative rate;
- balanced accuracy;
- p50/p95/p99/max latency;
- deterministic percentile bootstrap confidence intervals.

### Build 19 — Ground-truth contract

`core/evaluation_corpus.py` enforces:

- stable case identity;
- label and label-confidence vocabulary;
- explicit evaluation split;
- source SHA-256;
- timezone-aware collection timestamps;
- environment and provenance;
- adversarial status;
- duplicate/near-duplicate grouping;
- cross-split leakage prevention.

`scripts/validate_ground_truth.py` is a CI gate.

### Build 20 — Score evaluation

When detector scores exist, the evaluator reports:

- AUROC;
- AUPRC;
- Brier score;
- expected calibration error (ECE).

Metrics are explicitly reported as undefined when the corpus lacks the required class diversity rather than fabricating a number.

### Build 21 — Corpus validation

A JSONL fixture proves the schema, provenance fields, and leakage controls. The fixture is synthetic and intentionally not treated as production evidence.

### Build 22 — Threshold calibration

`core/thresholds.py` supports reproducible tuning-set threshold selection using either:

- Youden's J statistic; or
- constrained recall with a maximum false-positive rate.

The selected threshold is a tuning artifact and must be frozen before final test evaluation.

### Build 23 — Adversarial regression harness

`benchmarks/adversarial.py` applies bounded deterministic jitter, scaling, and noise perturbations to synthetic scenarios. It is intended to catch brittle regressions before independent red/purple-team testing.

## Evaluation layers

### Layer 1 — deterministic regression

Known synthetic scenarios, malformed/short inputs, metric unit tests and schema tests.

### Layer 2 — repeated synthetic evaluation

`benchmarks/benchmark.py` runs 100 deterministic seeds per scenario and reports quality, uncertainty and latency.

### Layer 3 — labeled real traffic

The repository now provides the data contract and validation machinery. Real PCAP/telemetry datasets must be supplied with provenance, labeling authority, confidence, source hashes, collection context, and partition hygiene.

### Layer 4 — threat-informed/purple-team evaluation

Use ATT&CK-aligned adversary emulation and controlled exercises. MITRE publishes adversary-emulation plans specifically to help defenders test products and environments against modeled adversary behavior. urlMITRE adversary emulation planshttps://attack.mitre.org/resources/adversary-emulation-plans/

## Metrics policy

**Primary:** recall/sensitivity and false-positive rate.

**Supporting:** precision, specificity, F1, balanced accuracy, false-negative rate, AUROC, AUPRC, Brier score, ECE and latency percentiles.

A headline accuracy value must never be presented without support counts and class composition.

## Anti-patterns

Do not:

- report synthetic accuracy as universal detection accuracy;
- tune thresholds on the final test set;
- allow source hashes or duplicate groups across partitions;
- hide false positives by excluding difficult benign traffic;
- publish aggregate metrics without sample counts;
- claim independent validation without an independent evaluator;
- compare products using incomparable corpora/configurations;
- treat bounded synthetic perturbations as evidence of real-world adversarial resilience.

## Current evidence boundary

Group 2 establishes the **evaluation machinery and regression gates**. It does not claim production detection performance. Real-world labeled-corpus validation, external datasets, adversarial evasion testing, independent purple-team validation, and customer-scale performance validation remain required evidence for enterprise assurance.
