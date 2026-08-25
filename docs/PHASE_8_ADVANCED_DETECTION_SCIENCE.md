# ThreatFade Phase 8 — Advanced Detection Science

## Decision

Phase 8 is an **experimental research track**, not a production ML replacement. The existing statistical/fade detection pipeline remains authoritative unless an experimentally evaluated model demonstrates material improvement on ThreatFade-relevant held-out data and passes the promotion gates in this document.

## Research review

| Method | Potential fit | Current decision |
|---|---|---|
| Statistical / temporal features | Directly aligned with fade behavior | **Production baseline** |
| Isolation Forest | Useful unsupervised comparator for environment-specific anomalies | **Experimental** |
| Sequence models / temporal transformers | Potential value for long temporal dependencies | Research only; requires ThreatFade-specific longitudinal corpus |
| Temporal GNNs | Potential value for evolving host/session relationships | Research only; graph topology is not yet sufficiently validated for the core fade problem |
| Self-supervised learning | Potential value where labels are sparse | Research only; pretext task must not leak attack labels |
| Continual learning | Potential value for environmental drift | Research only; poisoning and rollback risks require stronger controls |
| Federated learning | Potential value for cross-tenant learning without raw-data sharing | Deferred; aggregation/privacy threat model required |
| Adversarial training / robustness | Required security discipline for any promoted model | **Mandatory gate** |
| Explainability | Required for analyst trust and evidence interpretation | **Mandatory gate** |

Recent literature reports promising results for temporal graph approaches in evolving network environments, but those results are not transferable performance evidence for ThreatFade. For example, 2026 peer-reviewed work evaluates temporal GNNs for intrusion detection in IIoT/5G and VANET settings; the datasets, threat models and objectives differ from fade-window detection. The project therefore treats these methods as hypotheses to test, not as features to advertise.

NIST's 2025 adversarial-ML taxonomy explicitly covers poisoning, evasion and lifecycle risks. Those risks apply to ThreatFade model training and inference and are part of the promotion gate.

## Evaluation protocol

### Dataset provenance

Every experiment requires a `DatasetManifest` containing:

- dataset identifier and version
- provenance description
- feature schema version
- split policy
- deterministic seed
- manifest SHA-256 digest

### Leakage control

The default split is chronological rather than random. Model fitting is restricted to the training window. Unsupervised anomaly models are fitted only on benign training observations. Test observations are never used to fit preprocessing, thresholds or model parameters.

### Metrics

Every candidate is evaluated on held-out data using:

- ROC-AUC
- average precision
- precision
- recall
- F1
- threshold
- calibration status
- robustness status
- explainability status

Accuracy alone is intentionally not a promotion criterion.

### Promotion rule

A candidate must improve both average precision and F1 by at least **0.02 absolute** against the statistical baseline on the same held-out corpus, and must also pass:

1. calibration evaluation;
2. adversarial robustness evaluation;
3. explainability verification;
4. provenance/model-version checks;
5. rollback verification;
6. reproducibility verification.

Failure of any gate means **do not promote**.

The current experimental Isolation Forest comparator is therefore not a production replacement merely because the repository already contains an Isolation Forest artifact.

## Model lifecycle

`dataset manifest → deterministic split → feature contract → train → held-out evaluation → calibration → robustness → explainability → promotion decision → versioned artifact → rollback`

No experiment is permitted to silently mutate the production detector.

## Security controls

ML experiments must account for:

- data poisoning
- label manipulation
- train/test contamination
- feature leakage
- adversarial examples
- model/artifact substitution
- threshold manipulation
- nondeterminism
- sensitive-data leakage
- tenant crossover

Production inference must fail closed to the established statistical path if an experimental artifact is missing, invalid, incompatible with the feature schema, or fails integrity verification.

## Current implementation

`core/ml_experiments.py` supplies the governed experimental harness. `tests/test_ml_experiments.py` verifies deterministic chronological splitting, provenance digest stability, leakage-safe training boundaries and the conservative promotion gate. `.github/workflows/phase8-ml-experiments.yml` executes the governance tests in CI.

No GNN, transformer, self-supervised, continual-learning or federated model is promoted in this phase. Those approaches require additional ThreatFade-specific data and independent evidence before shipping.

## Evidence boundary

Synthetic CI fixtures validate the **correctness of the experiment machinery**, not detection quality in production. A CI pass must never be represented as evidence that a candidate model improves ThreatFade's real-world detection rate.

## References

- NIST AI 100-2 E2025, *Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations*.
- Yao & Koirala (2026), *Defense-Aware Temporal Graph Neural Network for fault-tolerant intrusion detection in IIoT–5G environments*, Cluster Computing.
- Linh et al. (2026), *DATZ-TM: Zero-Trust intrusion detection for VANETs with temporal graph neural networks*, Scientific Reports.
- Hernandez-Ramos et al. (2023), *Intrusion Detection based on Federated Learning: a systematic review*.
