import pytest
import numpy as np
from core.fade_engine import (
    detect_fade, calculate_entropy, calculate_drop_ratio,
    detect_zscore_outliers, compute_confidence,
)

class TestFadeDetection:
    def test_known_fade_detection(self):
        ts = list(range(100))
        vals = [0.9] * 20 + [0.05] * 60 + [0.9] * 20
        result = detect_fade(ts, vals)
        assert result["detected"] is True
        assert result["score"] > 0.15

    def test_no_fade_detection(self):
        result = detect_fade(list(range(100)), [0.8] * 100)
        assert result["drop_ratio"] < 0.1

    def test_minimum_data_points(self):
        result = detect_fade(list(range(5)), [0.5] * 5)
        assert result["detected"] is False
        assert result["score"] == 0.0
        assert result["confidence"] == "info"

    def test_entropy_calculation(self):
        vals = [0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1]
        entropy = calculate_entropy(vals, window=8)
        assert len(entropy) == 1
        assert entropy[0] > 0

    def test_drop_ratio_high(self):
        assert calculate_drop_ratio([0.1, 0.2, 0.1, 0.3, 0.2], threshold=0.5) == 1.0

    def test_drop_ratio_low(self):
        assert calculate_drop_ratio([0.8, 0.9, 0.7, 0.6, 0.8], threshold=0.5) == 0.0

    def test_zscore_outliers(self):
        vals = [0.5] * 50 + [5.0]
        _, max_z = detect_zscore_outliers(vals)
        assert max_z > 2.0

    def test_c2_quieting_pattern(self):
        vals = [0.9] * 20 + [0.1] * 60 + [0.9] * 20
        result = detect_fade(list(range(100)), vals)
        assert result["detected"] is True

    def test_lotl_gradual_pattern(self):
        vals = [0.9 - (i * 0.008) for i in range(100)]
        result = detect_fade(list(range(100)), vals)
        assert result["detected"] is True

    def test_false_positive_rejection(self):
        result = detect_fade(list(range(100)), [0.9] * 100)
        assert result["drop_ratio"] < 0.05

    def test_result_structure(self):
        result = detect_fade(list(range(100)), [0.5] * 100)
        for key in ["detected", "score", "confidence", "entropy", "drop_ratio",
                     "z_outlier", "fade_start", "rules_matched",
                     "entropy_score", "drop_score", "zscore_score"]:
            assert key in result

    def test_score_range(self):
        vals = [0.9] * 20 + [0.05] * 60 + [0.9] * 20
        result = detect_fade(list(range(100)), vals)
        assert 0.0 <= result["score"] <= 1.0

class TestConfidence:
    def test_critical_confidence(self):
        assert compute_confidence(0.6, 3, 15.0, 0.7) == "critical"

    def test_high_confidence(self):
        assert compute_confidence(0.5, 2, 5.0, 0.3) == "high"

    def test_medium_confidence(self):
        assert compute_confidence(0.3, 1, 2.0, 0.4) == "medium"

    def test_low_confidence(self):
        assert compute_confidence(0.1, 0, 1.0, 0.1) == "info"

class TestEdgeCases:
    def test_empty_signal(self):
        result = detect_fade([], [])
        assert result["detected"] is False

    def test_all_zeros(self):
        result = detect_fade(list(range(20)), [0.0] * 20)
        assert isinstance(result["detected"], bool)

    def test_extreme_values(self):
        result = detect_fade(list(range(20)), [1e6] * 10 + [1e-6] * 10)
        assert isinstance(result["score"], float)

    def test_single_value_repeated(self):
        result = detect_fade(list(range(50)), [0.42] * 50)
        assert isinstance(result["confidence"], str)

class TestConfiguration:
    def test_custom_config(self):
        config = {"entropy_window": 4, "min_points": 8, "threshold": 0.15,
                  "drop_weight": 0.5, "entropy_weight": 0.3, "zscore_weight": 0.2,
                  "rule_threshold": 0}
        vals = [0.8] * 20 + [0.1] * 30
        result = detect_fade(list(range(50)), vals, config=config)
        assert result["detected"] is True

    def test_strict_config_rejects(self):
        config = {"entropy_window": 8, "min_points": 12, "threshold": 0.9,
                  "drop_weight": 0.5, "entropy_weight": 0.3, "zscore_weight": 0.2,
                  "rule_threshold": 5}
        result = detect_fade(list(range(50)), [0.6] * 50, config=config)
        assert result["detected"] is False
