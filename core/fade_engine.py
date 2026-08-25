"""ThreatFade fade detection engine.

The legacy entropy/z-score detector remains deterministic and backwards
compatible. Detection Science 2.0 adds temporal, baseline and beacon evidence
without treating any anomaly score as a calibrated probability.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Tuple

import numpy as np
from scipy import stats

from core.detection_science import (
    AdaptiveBaseline,
    behavioral_evidence,
    combine_evidence,
    extract_beacon_features,
    extract_temporal_features,
)


def calculate_entropy(values: List[float], window: int = 8) -> np.ndarray:
    """Vectorized Shannon entropy over sliding windows."""
    if len(values) < window:
        return np.array([0.0])
    values = np.asarray(values, dtype=np.float64)
    if not np.all(np.isfinite(values)):
        raise ValueError("signal values must be finite")
    windows = np.lib.stride_tricks.sliding_window_view(values, window)
    abs_vals = np.abs(windows)
    totals = abs_vals.sum(axis=1)
    totals = np.where(totals == 0, 1, totals)
    normalized = abs_vals / totals[:, np.newaxis]
    log_p = np.log2(normalized + 1e-10)
    return -np.sum(normalized * log_p, axis=1)


def calculate_drop_ratio(values: List[float], threshold: float = 0.5) -> float:
    if len(values) == 0:
        return 0.0
    arr = np.asarray(values, dtype=np.float64)
    if not np.all(np.isfinite(arr)):
        raise ValueError("signal values must be finite")
    return float(np.mean(arr < threshold))


def detect_zscore_outliers(values: List[float]) -> Tuple[np.ndarray, float]:
    if len(values) < 3:
        return np.array([0.0]), 0.0
    arr = np.asarray(values, dtype=np.float64)
    if not np.all(np.isfinite(arr)):
        raise ValueError("signal values must be finite")
    if float(np.std(arr)) <= 1e-12:
        return np.zeros(len(arr)), 0.0
    z_scores = np.abs(stats.zscore(arr))
    if not np.all(np.isfinite(z_scores)):
        return np.zeros(len(arr)), 0.0
    return z_scores, float(np.max(z_scores)) if len(z_scores) > 0 else 0.0


def match_rules(values: List[float], entropy_vals: np.ndarray, config: Dict) -> int:
    rules_matched = 0
    if int(np.sum(entropy_vals < 0.3)) >= 3:
        rules_matched += 1
    drop_ratio = calculate_drop_ratio(values, threshold=0.5)
    if drop_ratio >= 0.55:
        rules_matched += 1
    if len(values) > 10:
        mid = len(values) // 2
        first_half_mean = float(np.mean(values[:mid]))
        second_half_mean = float(np.mean(values[mid:]))
        if first_half_mean < 0.3 and second_half_mean > 0.6:
            rules_matched += 1
    return rules_matched


def find_fade_start(entropy_vals: np.ndarray, values: List[float]) -> int:
    for i in range(len(entropy_vals) - 2):
        if entropy_vals[i] < 0.3 and entropy_vals[i + 1] < 0.3:
            return i
    return len(values) // 2


def compute_confidence(total_score, rules_matched, max_zscore, drop_ratio):
    signals = 0
    if total_score >= 0.4:
        signals += 2
    elif total_score >= 0.25:
        signals += 1
    if rules_matched >= 2:
        signals += 2
    elif rules_matched >= 1:
        signals += 1
    if max_zscore >= 10:
        signals += 2
    elif max_zscore >= 3:
        signals += 1
    if drop_ratio >= 0.5:
        signals += 1
    if signals >= 6:
        return "critical"
    if signals >= 4:
        return "high"
    if signals >= 2:
        return "medium"
    if signals >= 1:
        return "low"
    return "info"


def _default_config() -> dict:
    return {
        "entropy_window": 8,
        "min_points": 12,
        "threshold": 0.20,
        "drop_weight": 0.50,
        "entropy_weight": 0.30,
        "zscore_weight": 0.20,
        "rule_threshold": 2,
        "science_v2": True,
        "science_weight": 0.35,
        "low_signal_threshold": 0.5,
    }


def _numeric_timestamps(timestamps):
    """Convert timezone-aware datetimes or numeric timestamps to seconds."""
    values = []
    for value in timestamps:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError("timestamps must be timezone-aware")
            values.append(value.timestamp())
        else:
            values.append(float(value))
    return values


def _science_features(timestamps, values, config):
    temporal = extract_temporal_features(values, low_signal_threshold=float(config.get("low_signal_threshold", 0.5)))
    beacon = None
    try:
        if timestamps is not None and len(timestamps) >= 2:
            beacon = extract_beacon_features(_numeric_timestamps(timestamps))
    except (TypeError, ValueError, OverflowError):
        beacon = None
    baseline = AdaptiveBaseline(min_support=max(4, min(8, len(values) // 2)))
    edge = max(1, int(round(len(values) * 0.2)))
    baseline_values = np.asarray(values[:edge], dtype=np.float64)
    baseline.mean = float(np.mean(baseline_values))
    baseline.variance = float(np.var(baseline_values))
    baseline.support = int(edge)
    baseline_evidence = baseline.evidence(float(np.mean(values[-edge:])))
    behavior = behavioral_evidence(temporal, beacon)
    return temporal, beacon, baseline_evidence, behavior


def detect_fade(timestamps, values, config=None):
    cfg = _default_config()
    if config is not None:
        cfg.update(config)
    if len(values) < cfg["min_points"]:
        return {"detected": False, "score": 0.0, "confidence": "info", "entropy": 0.0, "drop_ratio": 0.0, "z_outlier": 0.0, "fade_start": -1, "rules_matched": 0, "entropy_score": 0.0, "drop_score": 0.0, "zscore_score": 0.0, "science_score": 0.0, "science_components": {}}

    entropy_vals = calculate_entropy(values, cfg["entropy_window"])
    avg_entropy = float(np.mean(entropy_vals))
    drop_ratio = calculate_drop_ratio(values, threshold=0.5)
    _, max_zscore = detect_zscore_outliers(values)
    rules_matched = match_rules(values, entropy_vals, cfg)
    entropy_score = float(min(1.0, max(0.0, 1.0 - (avg_entropy / 3.0))))
    drop_score = float(drop_ratio)
    zscore_score = float(min(1.0, max_zscore / 10.0))
    legacy_score = float(cfg["entropy_weight"] * entropy_score + cfg["drop_weight"] * drop_score + cfg["zscore_weight"] * zscore_score)

    temporal, beacon, baseline_evidence, behavior = _science_features(timestamps, values, cfg)
    science_score, components = combine_evidence(rule_score=legacy_score, baseline_score=baseline_evidence.deviation_score, behavioral=behavior)
    combined_score = legacy_score
    if cfg.get("science_v2", True):
        weight = float(np.clip(cfg.get("science_weight", 0.35), 0.0, 1.0))
        combined_score = (1.0 - weight) * legacy_score + weight * science_score

    detected = bool(combined_score >= cfg["threshold"] or rules_matched >= cfg["rule_threshold"])
    fade_start = temporal.change_point_index if detected and temporal.change_point_index >= 0 else (find_fade_start(entropy_vals, values) if detected else -1)
    confidence = compute_confidence(combined_score, rules_matched, max_zscore, drop_ratio)
    return {
        "detected": detected, "score": float(combined_score), "confidence": confidence,
        "entropy": avg_entropy, "drop_ratio": drop_ratio, "z_outlier": float(max_zscore),
        "fade_start": int(fade_start), "rules_matched": int(rules_matched),
        "entropy_score": entropy_score, "drop_score": drop_score, "zscore_score": zscore_score,
        "legacy_score": legacy_score, "science_score": float(science_score),
        "science_components": components, "temporal_features": temporal.to_dict(),
        "baseline_evidence": baseline_evidence.to_dict(), "beacon_features": beacon.to_dict() if beacon else {},
    }


def detect_fade_with_ml(timestamps, values, config=None, ml_detector=None):
    """Extended detection with optional Isolation Forest evidence."""
    result = detect_fade(timestamps, values, config)
    ml_score = 0.0
    ml_anomaly = False
    ml_available = False
    if ml_detector is not None:
        try:
            ml_score, ml_anomaly = ml_detector.predict(values)
            ml_available = True
        except Exception:
            ml_score, ml_anomaly = 0.0, False
    result["ml_score"] = float(ml_score)
    result["ml_anomaly"] = bool(ml_anomaly)
    result["ml_available"] = bool(ml_available)
    if ml_available:
        base = float(result["science_score"])
        result["science_score_with_ml"] = float(min(1.0, 0.96 * base + 0.04 * np.clip(ml_score, 0.0, 1.0)))
    else:
        result["science_score_with_ml"] = result["science_score"]
    if ml_available and ml_anomaly and result["detected"]:
        score = result["score"]
        result["combined_confidence"] = "critical" if score >= 0.4 or ml_score >= 0.6 else ("high" if score >= 0.25 or ml_score >= 0.4 else "medium")
    elif result["detected"]:
        result["combined_confidence"] = result["confidence"]
    else:
        result["combined_confidence"] = "info"
    return result
