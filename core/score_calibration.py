"""Detection score calibration helpers.

Calibration is intentionally separate from detection. Raw anomaly scores are
not probabilities. A calibrator may only be fitted on an explicitly supplied
tuning partition and must then be frozen before final evaluation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np

try:
    from sklearn.isotonic import IsotonicRegression
except ImportError:  # pragma: no cover - dependency is part of production requirements
    IsotonicRegression = None


@dataclass(frozen=True)
class CalibrationReport:
    method: str
    tuning_support: int
    positive_support: int
    negative_support: int
    brier_score: float
    monotonic: bool
    frozen: bool

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _validate(scores: Sequence[float], labels: Sequence[bool]) -> tuple[np.ndarray, np.ndarray]:
    x = np.asarray(list(scores), dtype=np.float64)
    y = np.asarray([int(v) for v in labels], dtype=np.int8)
    if x.ndim != 1 or y.ndim != 1 or x.size != y.size:
        raise ValueError("scores and labels must be equal-length one-dimensional sequences")
    if x.size < 4:
        raise ValueError("at least four tuning observations are required")
    if not np.all(np.isfinite(x)):
        raise ValueError("scores must be finite")
    if not np.all(np.isin(y, [0, 1])):
        raise ValueError("labels must be binary")
    if len(np.unique(y)) < 2:
        raise ValueError("calibration requires both positive and negative tuning examples")
    return np.clip(x, 0.0, 1.0), y


class ScoreCalibrator:
    """Frozen isotonic calibrator for anomaly scores in [0, 1]."""

    def __init__(self) -> None:
        self._model = None
        self._frozen = False
        self._report: CalibrationReport | None = None

    @property
    def fitted(self) -> bool:
        return self._model is not None

    @property
    def frozen(self) -> bool:
        return self._frozen

    def fit(self, scores: Sequence[float], labels: Sequence[bool]) -> CalibrationReport:
        if self._frozen:
            raise RuntimeError("calibrator is frozen")
        if IsotonicRegression is None:
            raise RuntimeError("scikit-learn is required for score calibration")
        x, y = _validate(scores, labels)
        model = IsotonicRegression(y_min=0.0, y_max=1.0, increasing=True, out_of_bounds="clip")
        model.fit(x, y)
        calibrated = np.asarray(model.predict(x), dtype=np.float64)
        report = CalibrationReport(
            method="isotonic_regression",
            tuning_support=int(x.size),
            positive_support=int(y.sum()),
            negative_support=int(y.size - y.sum()),
            brier_score=float(np.mean((calibrated - y) ** 2)),
            monotonic=True,
            frozen=False,
        )
        self._model = model
        self._report = report
        return report

    def freeze(self) -> CalibrationReport:
        if self._model is None or self._report is None:
            raise RuntimeError("calibrator must be fitted before freezing")
        self._frozen = True
        self._report = CalibrationReport(**{**self._report.to_dict(), "frozen": True})
        return self._report

    def transform(self, scores: Sequence[float] | float) -> np.ndarray | float:
        if self._model is None:
            raise RuntimeError("calibrator is not fitted")
        arr = np.asarray([scores] if np.isscalar(scores) else list(scores), dtype=np.float64)
        if not np.all(np.isfinite(arr)):
            raise ValueError("scores must be finite")
        result = np.asarray(self._model.predict(np.clip(arr, 0.0, 1.0)), dtype=np.float64)
        return float(result[0]) if np.isscalar(scores) else result

    def report(self) -> CalibrationReport:
        if self._report is None:
            raise RuntimeError("calibrator is not fitted")
        return self._report
