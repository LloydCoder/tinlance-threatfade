"""Detection evaluation primitives for reproducible ThreatFade validation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

import numpy as np


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    scenario: str
    expected_detection: bool
    detected: bool
    latency_ms: Optional[float] = None
    score: Optional[float] = None


@dataclass(frozen=True)
class ConfusionMatrix:
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    @property
    def total(self) -> int:
        return self.true_positive + self.false_positive + self.true_negative + self.false_negative


def confusion_matrix(cases: Sequence[EvaluationCase]) -> ConfusionMatrix:
    tp = fp = tn = fn = 0
    for case in cases:
        if case.expected_detection and case.detected:
            tp += 1
        elif not case.expected_detection and case.detected:
            fp += 1
        elif not case.expected_detection and not case.detected:
            tn += 1
        else:
            fn += 1
    return ConfusionMatrix(tp, fp, tn, fn)


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def classification_metrics(matrix: ConfusionMatrix) -> dict:
    tp, fp, tn, fn = matrix.true_positive, matrix.false_positive, matrix.true_negative, matrix.false_negative
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    f1 = _safe_div(2.0 * precision * recall, precision + recall)
    accuracy = _safe_div(tp + tn, matrix.total)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, fn + tp)
    return {"support": matrix.total, "positive_support": tp + fn, "negative_support": tn + fp, "true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn, "accuracy": accuracy, "precision": precision, "recall": recall, "sensitivity": recall, "specificity": specificity, "f1": f1, "false_positive_rate": fpr, "false_negative_rate": fnr, "balanced_accuracy": (recall + specificity) / 2.0}


def ranking_metrics(cases: Sequence[EvaluationCase]) -> dict:
    """Compute AUROC/AUPRC from detector scores without an ML dependency."""
    scored = [case for case in cases if case.score is not None and np.isfinite(case.score)]
    if not scored:
        return {"scored_support": 0, "auroc": None, "auprc": None}
    labels = np.asarray([int(case.expected_detection) for case in scored], dtype=np.int8)
    scores = np.asarray([float(case.score) for case in scored], dtype=np.float64)
    positives = int(labels.sum())
    negatives = int(len(labels) - positives)
    if positives == 0 or negatives == 0:
        return {"scored_support": len(scored), "auroc": None, "auprc": None}
    order = np.argsort(-scores, kind="mergesort")
    y = labels[order]
    s = scores[order]
    distinct = np.r_[True, s[1:] != s[:-1]]
    thresholds = np.flatnonzero(distinct)
    tp = np.cumsum(y)[thresholds]
    fp = np.cumsum(1 - y)[thresholds]
    tpr = np.r_[0.0, tp / positives, 1.0]
    fpr = np.r_[0.0, fp / negatives, 1.0]
    auroc = float(np.trapz(tpr, fpr))
    recall = np.r_[0.0, tp / positives]
    precision = np.r_[1.0, tp / np.maximum(tp + fp, 1)]
    auprc = float(np.trapz(precision, recall))
    return {"scored_support": len(scored), "auroc": auroc, "auprc": auprc}


def calibration_metrics(cases: Sequence[EvaluationCase], bins: int = 10) -> dict:
    """Report Brier score and expected calibration error for [0,1] scores."""
    if bins < 2:
        raise ValueError("bins must be at least 2")
    scored = [case for case in cases if case.score is not None and np.isfinite(case.score)]
    if not scored:
        return {"scored_support": 0, "brier_score": None, "ece": None, "bins": bins}
    scores = np.clip(np.asarray([float(case.score) for case in scored]), 0.0, 1.0)
    labels = np.asarray([int(case.expected_detection) for case in scored], dtype=np.float64)
    brier = float(np.mean((scores - labels) ** 2))
    ece = 0.0
    edges = np.linspace(0.0, 1.0, bins + 1)
    for index in range(bins):
        upper_mask = scores < edges[index + 1] if index < bins - 1 else scores <= edges[index + 1]
        mask = (scores >= edges[index]) & upper_mask
        if np.any(mask):
            ece += float(mask.mean()) * abs(float(scores[mask].mean()) - float(labels[mask].mean()))
    return {"scored_support": len(scored), "brier_score": brier, "ece": float(ece), "bins": bins}


def _metric_from_flags(expected: np.ndarray, detected: np.ndarray, metric: str) -> float:
    cases = [EvaluationCase(str(i), "bootstrap", bool(expected[i]), bool(detected[i])) for i in range(len(expected))]
    return float(classification_metrics(confusion_matrix(cases))[metric])


def bootstrap_confidence_interval(cases: Sequence[EvaluationCase], metric: str = "f1", confidence: float = 0.95, iterations: int = 2000, seed: int = 20260822) -> dict:
    if not 0 < confidence < 1:
        raise ValueError("confidence must be between 0 and 1")
    if iterations < 100:
        raise ValueError("iterations must be at least 100")
    if not cases:
        return {"metric": metric, "confidence": confidence, "lower": 0.0, "upper": 0.0, "estimate": 0.0, "iterations": 0}
    if metric not in classification_metrics(confusion_matrix(cases)):
        raise ValueError(f"unsupported classification metric: {metric}")
    expected = np.asarray([case.expected_detection for case in cases], dtype=np.bool_)
    detected = np.asarray([case.detected for case in cases], dtype=np.bool_)
    rng = np.random.default_rng(seed)
    estimates = np.empty(iterations, dtype=np.float64)
    size = len(cases)
    for i in range(iterations):
        sample = rng.integers(0, size, size=size)
        estimates[i] = _metric_from_flags(expected[sample], detected[sample], metric)
    alpha = (1.0 - confidence) / 2.0
    point = float(_metric_from_flags(expected, detected, metric))
    return {"metric": metric, "confidence": confidence, "lower": float(np.quantile(estimates, alpha)), "upper": float(np.quantile(estimates, 1.0 - alpha)), "estimate": point, "iterations": iterations, "seed": seed}


def latency_summary(cases: Sequence[EvaluationCase]) -> dict:
    latencies = [float(case.latency_ms) for case in cases if case.latency_ms is not None]
    if not latencies:
        return {"count": 0, "mean_ms": None, "p50_ms": None, "p95_ms": None, "p99_ms": None, "max_ms": None}
    values = np.asarray(latencies, dtype=np.float64)
    return {"count": int(values.size), "mean_ms": float(values.mean()), "p50_ms": float(np.quantile(values, 0.50)), "p95_ms": float(np.quantile(values, 0.95)), "p99_ms": float(np.quantile(values, 0.99)), "max_ms": float(values.max())}


def evaluate_cases(cases: Iterable[EvaluationCase], bootstrap: bool = True) -> dict:
    materialized: List[EvaluationCase] = list(cases)
    matrix = confusion_matrix(materialized)
    scenarios = {}
    for scenario in sorted({case.scenario for case in materialized}):
        subset = [case for case in materialized if case.scenario == scenario]
        scenarios[scenario] = classification_metrics(confusion_matrix(subset))
    result = {"corpus_size": len(materialized), "metrics": classification_metrics(matrix), "ranking": ranking_metrics(materialized), "calibration": calibration_metrics(materialized), "latency": latency_summary(materialized), "scenarios": scenarios}
    result["confidence_intervals"] = ({metric: bootstrap_confidence_interval(materialized, metric=metric) for metric in ("precision", "recall", "f1", "false_positive_rate")} if bootstrap and materialized else {})
    return result
