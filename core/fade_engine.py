"""
Fade Detection Engine
Detects threat fade using entropy, z-score, and rule-based analysis
"""

import numpy as np
from scipy import stats
from typing import Dict, List, Tuple, Any

def calculate_entropy(values: List[float], window: int = 8) -> np.ndarray:
    """
    Calculate rolling entropy of signal values
    
    Args:
        values: List of signal values
        window: Window size for entropy calculation
    
    Returns:
        Array of entropy values
    """
    entropy_vals = []
    for i in range(len(values) - window + 1):
        window_vals = values[i:i+window]
        # Normalize to probability distribution
        normalized = np.array(window_vals) / np.sum(np.abs(window_vals))
        # Shannon entropy (handle zeros)
        ent = -np.sum(normalized * np.log2(np.abs(normalized) + 1e-10))
        entropy_vals.append(ent)
    
    return np.array(entropy_vals)

def calculate_drop_ratio(values: List[float], threshold: float = 0.5) -> float:
    """
    Calculate ratio of signal drops (values below threshold)
    
    Args:
        values: List of signal values
        threshold: Drop threshold
    
    Returns:
        Ratio of drops
    """
    drops = sum(1 for v in values if v < threshold)
    return drops / len(values) if len(values) > 0 else 0.0

def detect_zscore_outliers(values: List[float]) -> Tuple[np.ndarray, float]:
    """
    Detect z-score outliers in signal
    
    Args:
        values: List of signal values
    
    Returns:
        Tuple of (z-scores, max outlier score)
    """
    z_scores = np.abs(stats.zscore(values))
    return z_scores, np.max(z_scores) if len(z_scores) > 0 else 0.0

def match_rules(values: List[float], entropy_vals: np.ndarray, config: Dict) -> int:
    """
    Apply rule-based detection
    
    Rules:
    1. Sustained low entropy (< 0.3 for 3+ consecutive windows)
    2. High drop ratio (> 0.4)
    3. Signal recovery after drop (re-spike after quiet period)
    
    Args:
        values: Signal values
        entropy_vals: Entropy values
        config: Detection config
    
    Returns:
        Number of rules matched
    """
    rules_matched = 0
    
    # Rule 1: Sustained low entropy
    low_entropy_windows = sum(1 for e in entropy_vals if e < 0.3)
    if low_entropy_windows >= 3:
        rules_matched += 1
    
    # Rule 2: High drop ratio
    drop_ratio = calculate_drop_ratio(values, threshold=0.5)
    if drop_ratio > 0.4:
        rules_matched += 1
    
    # Rule 3: Signal recovery after quiet (spike after drops)
    if len(values) > 10:
        mid = len(values) // 2
        first_half_mean = np.mean(values[:mid])
        second_half_mean = np.mean(values[mid:])
        if first_half_mean < 0.3 and second_half_mean > 0.6:
            rules_matched += 1
    
    return rules_matched

def find_fade_start(entropy_vals: np.ndarray, values: List[float]) -> int:
    """
    Find when fade started (first sustained low entropy point)
    
    Args:
        entropy_vals: Entropy values
        values: Signal values
    
    Returns:
        Index where fade likely started
    """
    for i in range(len(entropy_vals) - 2):
        if entropy_vals[i] < 0.3 and entropy_vals[i+1] < 0.3:
            return i
    return len(values) // 2  # Default to midpoint

def detect_fade(timestamps: List[float], values: List[float], config: Dict = None) -> Dict[str, Any]:
    """
    Main fade detection engine
    
    Combines entropy, z-score, and rule-based analysis to detect threat fade
    
    Args:
        timestamps: List of timestamps
        values: List of signal values
        config: Detection configuration (optional)
    
    Returns:
        Detection result dictionary
    """
    if config is None:
        config = {
            "entropy_window": 8,
            "min_points": 12,
            "threshold": 0.42,
            "drop_weight": 0.65,
            "entropy_weight": 0.25,
            "zscore_weight": 0.1,
            "rule_threshold": 2
        }
    
    # Ensure minimum data
    if len(values) < config["min_points"]:
        return {
            "detected": False,
            "score": 0.0,
            "entropy": 0.0,
            "drop_ratio": 0.0,
            "z_outlier": 0.0,
            "fade_start": -1
        }
    
    # Calculate metrics
    entropy_vals = calculate_entropy(values, config["entropy_window"])
    avg_entropy = np.mean(entropy_vals)
    drop_ratio = calculate_drop_ratio(values, threshold=0.5)
    z_scores, max_zscore = detect_zscore_outliers(values)
    rules_matched = match_rules(values, entropy_vals, config)
    
    # Weighted score (0-1)
    entropy_score = 1.0 - (avg_entropy / 3.0)  # Lower entropy = higher score
    entropy_score = min(1.0, max(0.0, entropy_score))
    
    drop_score = drop_ratio
    zscore_score = min(1.0, max_zscore / 10.0)
    
    total_score = (
        config["entropy_weight"] * entropy_score +
        config["drop_weight"] * drop_score +
        config["zscore_weight"] * zscore_score
    )
    
    # Detection decision
    detected = (
        total_score >= config["threshold"] and 
        rules_matched >= config["rule_threshold"]
    )
    
    fade_start = find_fade_start(entropy_vals, values) if detected else -1
    
    return {
        "detected": detected,
        "score": float(total_score),
        "entropy": float(avg_entropy),
        "drop_ratio": float(drop_ratio),
        "z_outlier": float(max_zscore),
        "fade_start": int(fade_start),
        "rules_matched": int(rules_matched),
        "entropy_score": float(entropy_score),
        "drop_score": float(drop_score),
        "zscore_score": float(zscore_score)
    }
