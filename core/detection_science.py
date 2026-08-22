"""ThreatFade Detection Science 2.0 primitives."""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Iterable, Mapping, Sequence

import numpy as np

EPSILON = 1e-12


@dataclass(frozen=True)
class TemporalFeatures:
    sample_count: int
    mean: float
    std: float
    coefficient_of_variation: float
    first_mean: float
    last_mean: float
    relative_change: float
    slope: float
    slope_zscore: float
    change_point_index: int
    fade_depth: float
    recovery_ratio: float
    low_signal_ratio: float
    longest_low_run: int
    difference_std: float
    lag1_autocorrelation: float

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass(frozen=True)
class BeaconFeatures:
    interval_count: int
    median_interval: float
    interval_cv: float
    jitter_ratio: float
    periodicity_score: float
    silence_ratio: float
    longest_silence: float

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass(frozen=True)
class BaselineEvidence:
    baseline_mean: float
    baseline_std: float
    robust_zscore: float
    deviation_score: float
    baseline_support: int

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _finite_array(values: Sequence[float] | Iterable[float]) -> np.ndarray:
    arr = np.asarray(list(values), dtype=np.float64)
    if arr.ndim != 1:
        raise ValueError("signal values must be one-dimensional")
    if arr.size and not np.all(np.isfinite(arr)):
        raise ValueError("signal values must be finite")
    return arr


def _safe_cv(values: np.ndarray) -> float:
    mean = float(np.mean(values)) if values.size else 0.0
    return float(np.std(values) / max(abs(mean), EPSILON)) if values.size else 0.0


def _longest_run(mask: np.ndarray) -> int:
    longest = current = 0
    for item in mask:
        if bool(item):
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _lag1_autocorrelation(values: np.ndarray) -> float:
    if values.size < 3:
        return 0.0
    left = values[:-1] - np.mean(values[:-1])
    right = values[1:] - np.mean(values[1:])
    denominator = float(np.linalg.norm(left) * np.linalg.norm(right))
    return float(np.dot(left, right) / denominator) if denominator > EPSILON else 0.0


def extract_temporal_features(values: Sequence[float] | Iterable[float], *, low_signal_threshold: float = 0.5, edge_fraction: float = 0.2) -> TemporalFeatures:
    """Extract stable temporal fade features with bounded runtime."""
    if not 0.0 < edge_fraction <= 0.5:
        raise ValueError("edge_fraction must be in (0, 0.5]")
    arr = _finite_array(values)
    n = int(arr.size)
    if n == 0:
        return TemporalFeatures(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, -1, 0.0, 0.0, 0.0, 0, 0.0, 0.0)

    mean = float(np.mean(arr))
    std = float(np.std(arr))
    edge = max(1, int(round(n * edge_fraction)))
    first_mean = float(np.mean(arr[:edge]))
    last_mean = float(np.mean(arr[-edge:]))
    relative_change = float((last_mean - first_mean) / max(abs(first_mean), EPSILON))

    x = np.arange(n, dtype=np.float64)
    x_centered = x - float(np.mean(x))
    denom = float(np.dot(x_centered, x_centered))
    slope = float(np.dot(x_centered, arr - mean) / denom) if denom > EPSILON else 0.0
    slope_zscore = float(abs(slope) * np.std(x) / max(std, EPSILON))

    change_point_index = -1
    if n >= 8 and std > EPSILON:
        prefix = np.cumsum(arr)
        candidate_count = min(4096, n - 7)
        candidates = np.linspace(4, n - 4, candidate_count, dtype=np.int64)
        candidates = np.unique(candidates)
        left_count = candidates.astype(np.float64)
        right_count = n - candidates
        left_mean = prefix[candidates - 1] / left_count
        right_mean = (prefix[-1] - prefix[candidates - 1]) / right_count
        shifts = np.abs(left_mean - right_mean) / std
        change_point_index = int(candidates[int(np.argmax(shifts))])

    low = arr < float(low_signal_threshold)
    low_signal_ratio = float(np.mean(low))
    longest_low_run = _longest_run(low)

    minimum = float(np.min(arr))
    fade_depth = float(max(0.0, first_mean - minimum) / max(abs(first_mean), EPSILON))
    recovery = max(0.0, last_mean - minimum)
    recovery_ratio = float(min(1.0, recovery / max(first_mean - minimum, EPSILON))) if first_mean > minimum else 0.0

    differences = np.diff(arr)
    difference_std = float(np.std(differences)) if differences.size else 0.0
    return TemporalFeatures(
        n, mean, std, _safe_cv(arr), first_mean, last_mean, relative_change,
        slope, slope_zscore, change_point_index, fade_depth, recovery_ratio,
        low_signal_ratio, longest_low_run, difference_std, _lag1_autocorrelation(arr),
    )


def extract_beacon_features(timestamps: Sequence[float] | Iterable[float], *, silence_multiplier: float = 2.5) -> BeaconFeatures:
    """Measure periodicity, jitter and silence in an event timestamp sequence."""
    ts = _finite_array(timestamps)
    if ts.size < 2:
        return BeaconFeatures(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    intervals = np.diff(ts)
    if np.any(intervals <= 0):
        raise ValueError("timestamps must be strictly increasing")
    med = float(np.median(intervals))
    cv = float(np.std(intervals) / max(abs(np.mean(intervals)), EPSILON))
    jitter = float(min(1.0, cv))
    periodicity = float(max(0.0, min(1.0, 1.0 - cv)))
    silence_threshold = med * float(silence_multiplier)
    silence = intervals > silence_threshold
    silence_ratio = float(np.mean(silence))
    longest_silence = float(np.max(intervals[silence])) if np.any(silence) else 0.0
    return BeaconFeatures(int(intervals.size), med, cv, jitter, periodicity, silence_ratio, longest_silence)


@dataclass
class AdaptiveBaseline:
    """Bounded EWMA baseline suitable for streaming signal features."""
    decay: float = 0.05
    min_support: int = 8
    mean: float | None = None
    variance: float = 0.0
    support: int = 0

    def __post_init__(self) -> None:
        if not 0.0 < self.decay <= 1.0:
            raise ValueError("decay must be in (0, 1]")
        if self.min_support < 1:
            raise ValueError("min_support must be positive")

    @property
    def std(self) -> float:
        return float(np.sqrt(max(self.variance, 0.0)))

    def update(self, value: float) -> None:
        value = float(value)
        if not isfinite(value):
            raise ValueError("baseline values must be finite")
        if self.mean is None:
            self.mean, self.variance, self.support = value, 0.0, 1
            return
        delta = value - self.mean
        alpha = self.decay
        self.mean += alpha * delta
        self.variance = (1.0 - alpha) * (self.variance + alpha * delta * delta)
        self.support += 1

    def evidence(self, value: float) -> BaselineEvidence:
        if self.mean is None:
            return BaselineEvidence(0.0, 0.0, 0.0, 0.0, 0)
        difference = abs(float(value) - self.mean)
        robust_scale = max(self.std, EPSILON)
        z = difference / robust_scale
        score = float(min(1.0, z / 4.0)) if self.support >= self.min_support else 0.0
        return BaselineEvidence(float(self.mean), self.std, float(z), score, self.support)

    def observe(self, value: float, *, update: bool = True) -> BaselineEvidence:
        evidence = self.evidence(value)
        if update:
            self.update(value)
        return evidence


def behavioral_evidence(temporal: TemporalFeatures, beacon: BeaconFeatures | None = None) -> Mapping[str, float]:
    """Return normalized evidence components; these are not probabilities."""
    sustained_drop = float(np.clip(max(0.0, -temporal.relative_change), 0.0, 1.0))
    change = float(np.clip(temporal.slope_zscore / 3.0, 0.0, 1.0))
    persistence = float(np.clip(temporal.longest_low_run / max(temporal.sample_count * 0.5, 1), 0.0, 1.0))
    recovery = float(np.clip(temporal.recovery_ratio, 0.0, 1.0))
    periodicity = float(beacon.periodicity_score if beacon else 0.0)
    periodicity_context = periodicity * max(sustained_drop, change, persistence)
    return {"sustained_drop": sustained_drop, "change_point": change, "persistence": persistence, "recovery": recovery, "periodicity": periodicity_context}


def combine_evidence(*, rule_score: float, baseline_score: float, behavioral: Mapping[str, float], ml_score: float = 0.0) -> tuple[float, dict[str, float]]:
    """Combine independent evidence into a bounded, explainable anomaly score."""
    components = {
        "rule": float(np.clip(rule_score, 0.0, 1.0)),
        "baseline": float(np.clip(baseline_score, 0.0, 1.0)),
        "sustained_drop": float(np.clip(behavioral.get("sustained_drop", 0.0), 0.0, 1.0)),
        "change_point": float(np.clip(behavioral.get("change_point", 0.0), 0.0, 1.0)),
        "persistence": float(np.clip(behavioral.get("persistence", 0.0), 0.0, 1.0)),
        "recovery": float(np.clip(behavioral.get("recovery", 0.0), 0.0, 1.0)),
        "periodicity": float(np.clip(behavioral.get("periodicity", 0.0), 0.0, 1.0)),
        "ml": float(np.clip(ml_score, 0.0, 1.0)),
    }
    score = (0.30 * components["rule"] + 0.18 * components["baseline"] + 0.18 * components["sustained_drop"] + 0.10 * components["change_point"] + 0.10 * components["persistence"] + 0.05 * components["periodicity"] + 0.04 * components["ml"] + 0.05 * components["recovery"])
    return float(np.clip(score, 0.0, 1.0)), components
