"""Evaluation and benchmark metrics for ThreatFade."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    label: str
    expected_detection: bool
    detected: bool
    score: float | None = None
    latency_ms: float | None = None
    scenario: str = "default"


def _classification_counts(cases: Sequence[EvaluationCase]) -> tuple[int, int, int, int]:
    tp = sum(case.expected_detection and case.detected for case in cases)
    tn = sum((not case.expected_detection) and (not case.detected) for case in cases)
    fp = sum((not case.expected_detection) and case.detected for case in cases)
    fn = sum(case.expected_detection and (not case.detected) for case in cases)
    return tp, tn, fp, fn


def classification_metrics(cases: Sequence[EvaluationCase]) -> dict:
    """Return deterministic classification metrics."""
    tp, tn, fp, fn = _classification_counts(cases)
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "support": total,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "accuracy": accuracy,
        "f1": f1,
    }


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
    auroc = float(np.trapezoid(tpr, fpr))
    recall = np.r_[0.0, tp / positives]
    precision = np.r_[1.0, tp / np.maximum(tp + fp, 1)]
    auprc = float(np.trapezoid(precision, recall))
    return {"scored_support": len(scored), "auroc": auroc, "auprc": auprc}


def calibration_metrics(cases: Sequence[EvaluationCase], bins: int = 10) -> dict:
    """Report Brier score and expected calibration error for [0,1] scores."""
    if bins < 2:
        raise ValueError("bins must be at least 2")
    scored = [case for case in cases if case.score is not None and np.isfinite(case.score)]
    if not scored:
        return {"scored_support": 0, "brier_score": None, "ece": None, "bins": bins}
    scores = np.asarray([float(case.score) for case in scored], dtype=np.float64)
    labels = np.asarray([int(case.expected_detection) for case in scored], dtype=np.float64)
    scores = np.clip(scores, 0.0, 1.0)
    brier = float(np.mean((scores - labels) ** 2))
    edges = np.linspace(0.0, 1.0, bins + 1)
    ece = 0.0
    for index in range(bins):
        lower = edges[index]
        upper = edges[index + 1]
        mask = (scores >= lower) & ((scores < upper) if index < bins - 1 else (scores <= upper))
        if not np.any(mask):
            continue
        ece += float(mask.mean()) * abs(float(scores[mask].mean()) - float(labels[mask].mean()))
    return {"scored_support": len(scored), "brier_score": brier, "ece": ece, "bins": bins}


def latency_summary(cases: Sequence[EvaluationCase]) -> dict:
    """Return deterministic latency summary statistics."""
    values = sorted(float(case.latency_ms) for case in cases if case.latency_ms is not None and np.isfinite(case.latency_ms))
    if not values:
        return {"count": 0, "p50_ms": None, "p95_ms": None, "max_ms": None}

    def percentile(percent: float) -> float:
        if len(values) == 1:
            return values[0]
        position = (len(values) - 1) * percent
        lower = int(np.floor(position))
        upper = int(np.ceil(position))
        if lower == upper:
            return values[lower]
        fraction = position - lower
        return values[lower] + (values[upper] - values[lower]) * fraction

    return {
        "count": len(values),
        "p50_ms": percentile(0.50),
        "p95_ms": percentile(0.95),
        "max_ms": values[-1],
    }


def ranking_metrics_with_bootstrap(cases: Sequence[EvaluationCase], bootstrap: bool = False) -> dict:
    """Compatibility wrapper used by callers that request bootstrap metadata."""
    result = ranking_metrics(cases)
    result["bootstrap"] = bool(bootstrap)
    return result


def evaluate_cases(cases: Sequence[EvaluationCase], bootstrap: bool = False) -> dict:
    """Build the complete evaluation report."""
    materialized = list(cases)
    matrix = classification_metrics(materialized)
    scenarios: dict[str, dict] = {}
    for scenario in sorted({case.scenario for case in materialized}):
        scenarios[scenario] = classification_metrics([case for case in materialized if case.scenario == scenario])
    return {
        "corpus_size": len(materialized),
        "metrics": matrix,
        "ranking": ranking_metrics(materialized),
        "calibration": calibration_metrics(materialized),
        "latency": latency_summary(materialized),
        "scenarios": scenarios,
        "bootstrap": bool(bootstrap),
    }
