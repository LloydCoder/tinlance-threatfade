"""Threshold calibration utilities for held-out ThreatFade evaluation.

Calibration must be performed on a tuning partition and frozen before the
final test partition is evaluated. The helpers therefore return an explicit
threshold plus the tuning-set evidence used to choose it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np

from core.evaluation import EvaluationCase


@dataclass(frozen=True)
class ThresholdResult:
    threshold: float
    objective: str
    tuning_support: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    def to_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "objective": self.objective,
            "tuning_support": self.tuning_support,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
        }


def calibrate_threshold(cases: Sequence[EvaluationCase], *, objective: str = "youden", max_false_positive_rate: float | None = None) -> ThresholdResult:
    """Select a score threshold using tuning data only.

    ``youden`` maximizes TPR-FPR. ``constrained_recall`` maximizes recall while
    respecting ``max_false_positive_rate``. Scores are required and must be
    finite. The caller is responsible for keeping the returned threshold away
    from the final test set until calibration is frozen.
    """
    if objective not in {"youden", "constrained_recall"}:
        raise ValueError("unsupported threshold objective")
    if objective == "constrained_recall" and max_false_positive_rate is None:
        raise ValueError("max_false_positive_rate is required for constrained_recall")
    if max_false_positive_rate is not None and not 0.0 <= max_false_positive_rate <= 1.0:
        raise ValueError("max_false_positive_rate must be between 0 and 1")
    scored = [case for case in cases if case.score is not None and np.isfinite(case.score)]
    if not scored:
        raise ValueError("threshold calibration requires scored cases")
    labels = np.asarray([int(case.expected_detection) for case in scored], dtype=np.int8)
    scores = np.asarray([float(case.score) for case in scored], dtype=np.float64)
    candidates = np.unique(np.clip(scores, 0.0, 1.0))
    candidates = np.r_[0.0, candidates, 1.0]
    best = None
    for threshold in candidates:
        predicted = scores >= threshold
        tp = int(np.sum((labels == 1) & predicted))
        fp = int(np.sum((labels == 0) & predicted))
        tn = int(np.sum((labels == 0) & ~predicted))
        fn = int(np.sum((labels == 1) & ~predicted))
        tpr = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        if objective == "youden":
            value = tpr - fpr
            feasible = True
        else:
            feasible = fpr <= float(max_false_positive_rate)
            value = tpr if feasible else -1.0
        candidate = (value, tpr, -fpr, -float(threshold), float(threshold), tp, fp, tn, fn)
        if feasible and (best is None or candidate > best):
            best = candidate
    if best is None:
        raise ValueError("no threshold satisfies the false-positive constraint")
    return ThresholdResult(best[4], objective, len(scored), best[5], best[6], best[7], best[8])
