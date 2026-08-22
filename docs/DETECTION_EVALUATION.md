# ThreatFade Detection Evaluation Standard

**Build:** Group 2 / Build 18  
**Status:** implemented baseline  
**Benchmark:** `synthetic-scenario-v2`

## Purpose

ThreatFade must distinguish a useful detection claim from a benchmark artifact. The evaluation framework therefore separates **ground truth**, **detector output**, **metrics**, **uncertainty**, and **scenario-level results**.

NIST SP 800-55 Vol. 1 and Vol. 2 recommend a deliberate measurement program for selecting, evaluating, and using security measures rather than relying on a single headline number. urlNIST SP 800-55 Vol. 1https://csrc.nist.gov/pubs/sp/800/55/v1/final urlNIST SP 800-55 Vol. 2https://csrc.nist.gov/pubs/sp/800/55/v2/final

MITRE's ATT&CK analytics guidance likewise emphasizes building, testing, and refining behavioral analytics using adversary emulation and threat-informed evaluation. urlMITRE ATT&CK detections and analyticshttps://attack.mitre.org/resources/get-started/detections-and-analytics/

## Evaluation layers

### Layer 1 — Deterministic unit/regression tests

Purpose: detect accidental logic regressions quickly.

Examples:

- known synthetic C2 quieting;
- LOTL gradual fade;
- GNSS jamming;
- benign temporary dip;
- malformed/short signal inputs.

### Layer 2 — Repeated synthetic evaluation

`benchmarks/benchmark.py` runs **100 deterministic seeds per scenario** and evaluates:

- true positives;
- false positives;
- true negatives;
- false negatives;
- accuracy;
- precision;
- recall/sensitivity;
- specificity;
- F1;
- false-positive rate;
- false-negative rate;
- balanced accuracy;
- p50/p95/p99 latency;
- bootstrap confidence intervals.

The current synthetic regression gate requires all labeled malicious scenarios to remain detectable and the known benign `normal_with_fade` scenario to remain free of false positives. This is a **regression gate**, not a claim of real-world accuracy.

### Layer 3 — Labeled real-traffic evaluation

Future real-PCAP evaluation must preserve:

- dataset provenance;
- collection environment;
- time range;
- sensor/source type;
- protocol mix;
- labeling authority;
- labeling confidence;
- duplicate/near-duplicate handling;
- train/tune/test separation;
- temporal holdout;
- environment holdout;
- adversarial/evasion status.

No test corpus should be tuned and evaluated on the same examples without a clearly documented limitation.

### Layer 4 — Threat-informed / purple-team evaluation

Future evaluations should use ATT&CK-aligned adversary emulation and controlled exercises. MITRE describes ATT&CK evaluations as rigorous, transparent, threat-informed purple-team assessments. urlMITRE ATT&CK Evaluationshttps://www.mitre.org/focus-areas/cybersecurity/mitre-attack

## Metrics policy

### Primary metrics

**Recall / sensitivity** is the primary metric for malicious scenario coverage because a missed fade event is a security failure.

**False-positive rate** is the primary operational guardrail because excessive noise can make a detection product unusable.

**Precision and F1** summarize alert quality but must be interpreted alongside class prevalence.

**Specificity** measures benign-case rejection.

**Balanced accuracy** is preferred over raw accuracy when evaluation corpora are imbalanced.

### Performance metrics

Record at least:

- p50 detection latency;
- p95 detection latency;
- p99 detection latency;
- maximum observed latency;
- throughput under defined workload;
- resource utilization in later load-testing builds.

## Confidence intervals

Point estimates alone are insufficient for small corpora. The evaluator uses deterministic percentile bootstrap intervals for classification metrics. The seed and iteration count are recorded so results are reproducible.

Confidence intervals describe uncertainty in the sampled evaluation corpus; they do not compensate for biased or unrepresentative ground truth.

## Scenario-level reporting

Every report must preserve per-scenario results. A strong aggregate result cannot hide a catastrophic failure against one scenario class.

Minimum scenario fields:

```text
scenario
support
true_positive
false_positive
true_negative
false_negative
precision
recall
specificity
f1
false_positive_rate
false_negative_rate
latency
```

## Ground-truth contract

A future labeled corpus record should include:

```yaml
case_id: stable identifier
scenario: threat behavior category
expected_detection: true|false
source: capture/sensor identifier
collection_start: timestamp
collection_end: timestamp
label: analyst/authoritative label
label_confidence: high|medium|low
provenance: dataset provenance reference
adversarial: true|false
notes: limitations or caveats
```

## Validation anti-patterns

Do not:

- report synthetic accuracy as universal detection accuracy;
- tune thresholds on the final test set;
- mix duplicate captures across train/tune/test partitions;
- hide false positives by excluding difficult benign traffic;
- publish aggregate metrics without sample counts;
- claim independent validation without an independent evaluator;
- compare products using incomparable corpora or configurations.

## Current evidence boundary

The repository currently has deterministic synthetic validation and repeated-seed regression coverage. Real-world labeled corpus validation, adversarial evasion testing, independent purple-team validation, and customer-scale performance validation remain future assurance work.
