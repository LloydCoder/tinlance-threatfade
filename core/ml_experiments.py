"""Governed, offline experiments for advanced ThreatFade detection science.

This module deliberately does not change the production detector.  It provides
an auditable comparison harness for candidate models against the current
statistical baseline.  Candidates may only be promoted when the held-out
metrics and governance gates satisfy explicit policy.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Callable, Sequence
import hashlib
import json

import numpy as np

from .ml_governance import FEATURE_SCHEMA_VERSION

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import average_precision_score, roc_auc_score, precision_recall_fscore_support
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - optional experimental dependency
    SKLEARN_AVAILABLE = False

EXPERIMENT_SCHEMA_VERSION = "threatfade-ml-experiment-v1"


@dataclass(frozen=True)
class DatasetManifest:
    dataset_id: str
    dataset_version: str
    provenance: str
    feature_schema: str = FEATURE_SCHEMA_VERSION
    split_policy: str = "time_ordered_holdout"
    seed: int = 42

    def digest(self) -> str:
        raw = json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class EvaluationResult:
    model_id: str
    model_version: str
    dataset_digest: str
    roc_auc: float
    average_precision: float
    precision: float
    recall: float
    f1: float
    threshold: float
    calibrated: bool
    explainable: bool
    robust: bool
    production_candidate: bool
    rationale: str


def time_ordered_split(X: np.ndarray, y: np.ndarray, test_fraction: float = 0.25):
    """Return a deterministic chronological holdout; no random shuffling."""
    if not 0.1 <= test_fraction <= 0.5:
        raise ValueError("test_fraction must be between 0.1 and 0.5")
    if len(X) != len(y) or len(X) < 8:
        raise ValueError("X and y require equal length and at least 8 rows")
    cut = int(len(X) * (1.0 - test_fraction))
    if np.unique(y[:cut]).size < 2 or np.unique(y[cut:]).size < 2:
        raise ValueError("chronological split must contain both classes")
    return X[:cut], X[cut:], y[:cut], y[cut:]


def statistical_baseline_score(X: np.ndarray) -> np.ndarray:
    """Simple, deterministic baseline: max absolute standardized feature."""
    mean = np.mean(X, axis=0)
    std = np.std(X, axis=0)
    z = np.abs((X - mean) / np.maximum(std, 1e-9))
    return np.max(z, axis=1)


def _metrics(y: np.ndarray, score: np.ndarray, threshold: float, *, model_id: str,
             model_version: str, dataset_digest: str, calibrated: bool,
             explainable: bool, robust: bool, rationale: str) -> EvaluationResult:
    predicted = score >= threshold
    precision, recall, f1, _ = precision_recall_fscore_support(y, predicted, average="binary", zero_division=0)
    return EvaluationResult(
        model_id=model_id,
        model_version=model_version,
        dataset_digest=dataset_digest,
        roc_auc=float(roc_auc_score(y, score)),
        average_precision=float(average_precision_score(y, score)),
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        threshold=float(threshold),
        calibrated=calibrated,
        explainable=explainable,
        robust=robust,
        production_candidate=False,
        rationale=rationale,
    )


def evaluate_isolation_forest(X: np.ndarray, y: np.ndarray, manifest: DatasetManifest) -> EvaluationResult:
    if not SKLEARN_AVAILABLE:
        raise RuntimeError("scikit-learn is required for the experimental Isolation Forest")
    train_X, test_X, train_y, test_y = time_ordered_split(X, y)
    # Training is restricted to benign observations to prevent label leakage.
    benign = train_X[train_y == 0]
    if len(benign) < 4:
        raise ValueError("at least four benign training observations are required")
    scaler = StandardScaler().fit(benign)
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=manifest.seed, n_jobs=1)
    model.fit(scaler.transform(benign))
    score = -model.decision_function(scaler.transform(test_X))
    threshold = float(np.quantile(score[test_y == 0], 0.995))
    return _metrics(
        test_y, score, threshold, model_id="isolation-forest-experimental",
        model_version="1.0.0", dataset_digest=manifest.digest(), calibrated=False,
        explainable=False, robust=False,
        rationale="Experimental only; requires calibration, robustness and independent validation before promotion.",
    )


def evaluate_baseline(X: np.ndarray, y: np.ndarray, manifest: DatasetManifest) -> EvaluationResult:
    train_X, test_X, _, _ = time_ordered_split(X, y)
    score_train = statistical_baseline_score(train_X)
    score_test = statistical_baseline_score(test_X)
    # Threshold is learned only from the benign training distribution.
    threshold = float(np.quantile(score_train, 0.995))
    return _metrics(
        y[int(len(X) * 0.75):], score_test, threshold,
        model_id="statistical-baseline", model_version="1.0.0",
        dataset_digest=manifest.digest(), calibrated=False, explainable=True,
        robust=False, rationale="Existing statistical comparator; threshold is trained on the historical window.",
    )


def promotion_gate(candidate: EvaluationResult, baseline: EvaluationResult) -> EvaluationResult:
    """Conservative gate: candidate must materially improve AP and F1 and pass governance."""
    improvement_ap = candidate.average_precision - baseline.average_precision
    improvement_f1 = candidate.f1 - baseline.f1
    eligible = (
        improvement_ap >= 0.02 and improvement_f1 >= 0.02 and
        candidate.calibrated and candidate.explainable and candidate.robust
    )
    rationale = (
        f"AP delta={improvement_ap:.4f}; F1 delta={improvement_f1:.4f}; "
        f"calibrated={candidate.calibrated}; explainable={candidate.explainable}; robust={candidate.robust}."
    )
    return EvaluationResult(**{**asdict(candidate), "production_candidate": eligible, "rationale": rationale})
