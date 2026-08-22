# Group 9 — Detection Science 2.0

**Status:** Implementation complete; release gate is hosted CI/security verification.  
**Baseline:** ThreatFade v0.7.x  
**Scope:** Temporal detection science, behavioral fade evidence, beacon/jitter evidence, adaptive baselines, explainable ensemble scoring, score calibration and adversarial regression.

## Why Group 9 exists

The original fade engine was intentionally small: rolling entropy, drop ratio, z-score and deterministic rules. That is a useful research baseline, but it does not sufficiently model the temporal and behavioral characteristics of a C2 fade window.

Detection Science 2.0 adds evidence without replacing the explainable baseline.

## Detection path

```text
ordered signal observations
        |
        +--> entropy / z-score / legacy rules
        |
        +--> temporal features
        |       - sustained change
        |       - slope / slope z-score
        |       - change point
        |       - persistence / longest low run
        |       - fade depth / recovery
        |
        +--> beacon features
        |       - interval distribution
        |       - jitter
        |       - periodicity
        |       - silence windows
        |
        +--> local adaptive baseline
        |
        +--> optional Isolation Forest evidence
        |
        `--> bounded explainable ensemble score
                    |
                    +--> detection / analyst evidence
                    `--> optional held-out score calibration
```

The output is an **anomaly score**, not a probability, unless a separately fitted and frozen calibrator is applied.

## Implemented controls

### Temporal evidence

`core/detection_science.py` provides deterministic extraction of:

- sample count
- mean and standard deviation
- coefficient of variation
- edge-window baseline change
- relative change
- normalized slope
- change-point index
- fade depth
- recovery ratio
- low-signal persistence
- longest low-signal run
- first-difference variability
- lag-1 autocorrelation

### Beacon and silence evidence

Ordered timestamps are used to measure:

- inter-arrival median
- interval coefficient of variation
- jitter ratio
- periodicity score
- extended silence ratio
- longest silence interval

Timestamp streams must be strictly increasing. Malformed timestamp metadata does not disable the underlying signal detector.

### Adaptive baseline

`AdaptiveBaseline` implements a bounded EWMA mean/variance model. It does not automatically update a baseline from a detection event as if the event were normal. The detector uses an initial edge window as local baseline evidence; future streaming integration must control baseline updates using analyst/trust state.

### Explainable ensemble

`combine_evidence()` combines:

- legacy deterministic rule score
- baseline deviation
- sustained drop
- change point
- persistence
- periodicity
- recovery context
- optional ML score

The deterministic evidence dominates the weighting. ML is capped as supporting evidence and cannot silently become the detection authority.

### Score calibration

`core/score_calibration.py` provides a held-out isotonic calibrator.

The lifecycle is:

```text
tuning scores + labels
        -> fit
        -> review calibration report
        -> freeze
        -> transform held-out / production scores
```

A frozen calibrator cannot be refit. Calibration is deliberately separate from detector threshold selection and must never be fitted on the final test partition.

## Validation

The repository now contains:

- `tests/test_detection_science.py`
- `tests/test_score_calibration.py`
- `benchmarks/detection_science_v2.py`
- `benchmarks/adversarial.py`
- `scripts/validate_detection_science.py`

The CI workflow executes the architecture gate, complete test suite, Detection Science 2.0 synthetic benchmark and adversarial synthetic benchmark.

## Limitations

This group does **not** claim:

- independent detection validation
- representative customer traffic coverage
- production-scale throughput proof
- universal false-positive or false-negative rates
- attacker-resistant detection against an adaptive real-world adversary
- calibrated probabilities from raw detector scores

Those require the real-world evidence and independent validation work planned for Group 10.

## Research basis

The architecture follows established network anomaly-detection principles: network behavior anomaly detection relies on a baseline of normal traffic and deviations from that baseline, while operational network monitoring benefits from baselining traffic, flows and device-to-device communication. NIST guidance describes this behavioral-baseline approach for network anomaly detection. urlNIST network anomaly detection guidancehttps://www.nccoe.nist.gov/sites/default/files/library/mf-ics-nistir-8219.pdf

Isolation Forest remains an optional anomaly layer. Its scores represent relative anomaly/normality rather than calibrated probabilities; scikit-learn documents lower scores as more abnormal and recommends interpreting the model through its decision/scoring semantics. urlscikit-learn IsolationForest documentationhttps://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
