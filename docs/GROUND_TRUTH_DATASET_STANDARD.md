# ThreatFade Ground-Truth Dataset Standard

**Group:** 2 — Detection Science & Validation  
**Builds:** 19–23  
**Status:** complete baseline

## Objective

A detection claim is only useful when the labeled evaluation data is traceable, partitioned correctly, and representative of the intended deployment context. ThreatFade therefore treats dataset provenance and partition hygiene as first-class security controls.

NIST's AI measurement guidance calls for documented test sets, metrics, methods, uncertainty, representative deployment conditions, and repeatable TEVV. urlNIST AI RMF Measurehttps://airc.nist.gov/airmf-resources/airmf/5-sec-core/ MITRE recommends threat-informed analytics that are built, tested and refined against adversary behavior rather than isolated indicators. urlMITRE ATT&CK detections and analyticshttps://attack.mitre.org/resources/get-started/detections-and-analytics/

## Required record fields

Every labeled case must contain:

- stable `case_id`;
- behavioral `scenario`;
- `label` (`malicious`, `benign`, or `unknown`);
- `label_confidence`;
- evaluation `split`;
- source identifier/type;
- SHA-256 of the source artifact;
- collection start/end timestamps with timezone;
- environment identifier;
- provenance reference;
- adversarial flag;
- optional duplicate/near-duplicate group;
- notes/limitations.

The schema is implemented in `core/evaluation_corpus.py`.

## Partition rules

A raw source hash may not cross `train`, `tune`, `test`, or `holdout`. Near-duplicate captures represented by a `duplicate_group` may not cross partitions either. This prevents direct and near-duplicate leakage from making a detector appear more generalizable than it is.

Threshold selection must use the tuning partition. Once frozen, the threshold must not be optimized against the final test partition.

## Evaluation layers

1. deterministic unit/regression tests;
2. repeated synthetic evaluation;
3. labeled real-traffic evaluation;
4. threat-informed/purple-team evaluation.

The current repository implements layers 1–2 and the contracts/tooling required for layer 3. It does **not** claim that the synthetic fixture is real-world traffic.

## Metrics

Primary:

- recall/sensitivity;
- false-positive rate.

Supporting:

- precision;
- specificity;
- F1;
- balanced accuracy;
- false-negative rate;
- AUROC;
- AUPRC;
- Brier score;
- expected calibration error;
- p50/p95/p99/max detection latency;
- bootstrap uncertainty intervals.

The score-ranking metrics are only reported when detector scores are available and both classes are represented.

## Robustness

`benchmarks/adversarial.py` applies deterministic bounded perturbations to synthetic scenarios. This is a regression harness, not an attacker-success estimate. Real evasion assessment remains an independent purple-team/red-team activity.

MITRE's adversary-emulation guidance supports using ATT&CK-based behavior to test defenses and refine analytics. urlMITRE adversary emulation planshttps://attack.mitre.org/resources/adversary-emulation-plans/

## Evidence boundary

The repository contains a small synthetic fixture solely to validate the data contract. No public metric in this repository should be interpreted as a claim of production detection performance until real, independently sourced, provenance-preserving datasets have been evaluated under the same protocol.
