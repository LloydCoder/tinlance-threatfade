"""
ThreatFade Test Suite
Unit tests for fade detection engine
"""

import pytest
import numpy as np
from core.fade_engine import (
    detect_fade,
    calculate_entropy,
    calculate_drop_ratio,
    detect_zscore_outliers
)

class TestFadeDetection:
    """Test suite for fade detection functionality"""
    
    def test_known_fade_detection(self):
        """Test detection on known fade scenario"""
        # Create signal with clear fade (high entropy drop)
        timestamps = list(range(100))
        values = [0.8] * 30 + [0.2] * 40 + [0.5] * 30
        
        result = detect_fade(timestamps, values)
        
        assert result["detected"] == True, "Should detect clear fade pattern"
        assert result["score"] > 0.2, "Score should be above threshold"
    
    def test_no_fade_detection(self):
        """Test normal signal (no fade)"""
        # Create stable signal
        timestamps = list(range(100))
        values = [0.7 + np.random.normal(0, 0.05) for _ in range(100)]
        
        result = detect_fade(timestamps, values)
        
        # Should not detect fade (or very low confidence)
        assert result["score"] < 0.5, "Stable signal should have low score"
    
    def test_minimum_data_points(self):
        """Test handling of insufficient data"""
        timestamps = [1, 2]
        values = [0.5, 0.6]
        
        result = detect_fade(timestamps, values)
        
        assert result["detected"] == False, "Too few points should not detect"
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        values = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
        entropy = calculate_entropy(values, window=4)
        
        assert len(entropy) > 0, "Should return entropy values"
        assert all(e >= 0 for e in entropy), "Entropy should be non-negative"
    
    def test_drop_ratio_high(self):
        """Test drop ratio on high-drop signal"""
        values = [0.1, 0.2, 0.1, 0.15, 0.1, 0.8, 0.75, 0.8]
        drop_ratio = calculate_drop_ratio(values, threshold=0.5)
        
        assert drop_ratio > 0.5, "High-drop signal should have high ratio"
    
    def test_drop_ratio_low(self):
        """Test drop ratio on low-drop signal"""
        values = [0.8] * 10
        drop_ratio = calculate_drop_ratio(values, threshold=0.5)
        
        assert drop_ratio == 0.0, "No drops should give 0 ratio"
    
    def test_zscore_outliers(self):
        """Test z-score outlier detection"""
        values = [0.5] * 20 + [5.0]  # One major outlier
        z_scores, max_z = detect_zscore_outliers(values)
        
        assert max_z > 2.0, "Outlier should have high z-score"
    
    def test_c2_quieting_pattern(self):
        """Test detection on C2 quieting pattern"""
        timestamps = list(range(60))
        # Normal -> quiet -> resume
        values = [0.7] * 15 + [0.15] * 25 + [0.5] * 20
        
        result = detect_fade(timestamps, values)
        
        assert result["detected"] == True, "Should detect C2 quieting"
        assert result["fade_start"] > 0, "Should identify fade start"
    
    def test_lotl_gradual_pattern(self):
        """Test detection on LOTL gradual decline"""
        timestamps = list(range(60))
        # Gradual linear decay
        values = [0.8 - (i * 0.01) for i in range(60)]
        
        result = detect_fade(timestamps, values)
        
        # LOTL may have lower score but should show signature
        assert result["drop_ratio"] > 0.3, "Should show signal drop"
    
    def test_false_positive_rejection(self):
        """Test that brief dips don't trigger false positives"""
        timestamps = list(range(60))
        # Normal with brief dip
        values = [0.75] * 25 + [0.4] * 10 + [0.75] * 25
        
        result = detect_fade(timestamps, values)
        
        # Brief dip shouldn't be classified as fade
        assert result["score"] < 0.5, "Brief dip shouldn't trigger high score"
    
    def test_result_structure(self):
        """Test that result has all required fields"""
        timestamps = list(range(50))
        values = [0.5] * 50
        
        result = detect_fade(timestamps, values)
        
        required_keys = [
            "detected", "score", "entropy", "drop_ratio",
            "z_outlier", "fade_start"
        ]
        
        for key in required_keys:
            assert key in result, f"Result missing {key}"
    
    def test_score_range(self):
        """Test that scores are in valid range"""
        timestamps = list(range(100))
        values = [np.random.random() for _ in range(100)]
        
        result = detect_fade(timestamps, values)
        
        assert 0.0 <= result["score"] <= 1.0, "Score should be 0-1"

class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_empty_signal(self):
        """Test handling of empty signal"""
        result = detect_fade([], [])
        assert result["detected"] == False
    
    def test_all_zeros(self):
        """Test signal with all zeros"""
        timestamps = list(range(50))
        values = [0.0] * 50
        
        result = detect_fade(timestamps, values)
        assert isinstance(result, dict)
    
    def test_extreme_values(self):
        """Test signal with extreme values"""
        timestamps = list(range(50))
        values = [1e10, 1e-10] * 25
        
        result = detect_fade(timestamps, values)
        assert "detected" in result

class TestConfiguration:
    """Test configuration handling"""
    
    def test_custom_config(self):
        """Test detection with custom config"""
        config = {
            "entropy_window": 4,
            "min_points": 8,
            "threshold": 0.5,
            "drop_weight": 0.5,
            "entropy_weight": 0.3,
            "zscore_weight": 0.2,
            "rule_threshold": 1
        }
        
        timestamps = list(range(50))
        values = [0.8] * 15 + [0.1] * 20 + [0.6] * 15
        
        result = detect_fade(timestamps, values, config)
        assert isinstance(result, dict)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
