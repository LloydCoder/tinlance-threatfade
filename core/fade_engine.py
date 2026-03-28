"""
Fade Detection Engine
Detects threat fade using entropy, z-score, and rule-based analysis.

Part of ThreatFade by Tinlance Limited.
"""

import numpy as np
from scipy import stats
from typing import Dict, List, Tuple, Any


def calculate_entropy(values: List[float], window: int = 8) -> np.ndarray:
    entropy_vals = []
    for i in range(len(values) - window + 1):
        window_vals = values[i : i + window]
        total = np.sum(np.abs(window_vals))
        if total == 0:
            entropy_vals.append(0.0)
            continue
        normalized = np.array(window_vals) / total
        ent = -np.sum(normalized * np.log2(np.abs(normalized) + 1e-10))
        entropy_vals.append(ent)
    return np.array(entropy_vals)


def calculate_drop_ratio(values: List[float], threshold: float = 0.5) -> float:
    if len(values) == 0:
        return 0.0
    drops = sum(1 for v in values if v < threshold)
    return drops / len(values)


def detect_zscore_outliers(values: List[float]) -> Tuple[np.ndarray, float]:
    if len(values) < 3:
        return np.array([0.0]), 0.0
    if np.std(values) == 0:
        return np.zeros(len(values)), 0.0
    z_scores = np.abs(stats.zscore(values))
    return z_scores, float(np.max(z_scores)) if len(z_scores) > 0 else 0.0


def match_rules(values: List[float], entropy_vals: np.ndarray, config: Dict) -> int:
    rules_matched = 0
    low_entropy_windows = sum(1 for e in entropy_vals if e < 0.3)
    if low_entropy_windows >= 3:
        rules_matched += 1
    drop_ratio = calculate_drop_ratio(values, threshold=0.5)
    if drop_ratio >= 0.55:
        rules_matched += 1
    if len(values) > 10:
        mid = len(values) // 2
        first_half_mean = np.mean(values[:mid])
        second_half_mean = np.mean(values[mid:])
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
    elif signals >= 4:
        return "high"
    elif signals >= 2:
        return "medium"
    elif signals >= 1:
        return "low"
    return "info"


def detect_fade(timestamps, values, config=None):
    if config is None:
        config = {
            "entropy_window": 8,
            "min_points": 12,
            "threshold": 0.20,
            "drop_weight": 0.50,
            "entropy_weight": 0.30,
            "zscore_weight": 0.20,
            "rule_threshold": 2,
        }
    if len(values) < config["min_points"]:
        return {
            "detected": False, "score": 0.0, "confidence": "info",
            "entropy": 0.0, "drop_ratio": 0.0, "z_outlier": 0.0,
            "fade_start": -1, "rules_matched": 0,
            "entropy_score": 0.0, "drop_score": 0.0, "zscore_score": 0.0,
        }
    entropy_vals = calculate_entropy(values, config["entropy_window"])
    avg_entropy = float(np.mean(entropy_vals))
    drop_ratio = calculate_drop_ratio(values, threshold=0.5)
    z_scores, max_zscore = detect_zscore_outliers(values)
    rules_matched = match_rules(values, entropy_vals, config)
    entropy_score = min(1.0, max(0.0, 1.0 - (avg_entropy / 3.0)))
    drop_score = drop_ratio
    zscore_score = min(1.0, max_zscore / 10.0)
    total_score = (
        config["entropy_weight"] * entropy_score
        + config["drop_weight"] * drop_score
        + config["zscore_weight"] * zscore_score
    )
    detected = (
        total_score >= config["threshold"]
        or rules_matched >= config["rule_threshold"]
    )
    fade_start = find_fade_start(entropy_vals, values) if detected else -1
    confidence = compute_confidence(total_score, rules_matched, max_zscore, drop_ratio)
    return {
        "detected": bool(detected), "score": float(total_score),
        "confidence": confidence, "entropy": float(avg_entropy),
        "drop_ratio": float(drop_ratio), "z_outlier": float(max_zscore),
        "fade_start": int(fade_start), "rules_matched": int(rules_matched),
        "entropy_score": float(entropy_score), "drop_score": float(drop_score),
        "zscore_score": float(zscore_score),
    }
