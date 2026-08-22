import numpy as np
import pytest

from core.detection_science import (
    AdaptiveBaseline,
    behavioral_evidence,
    combine_evidence,
    extract_beacon_features,
    extract_temporal_features,
)
from core.fade_engine import detect_fade


def test_temporal_features_capture_fade_and_recovery():
    values = [0.9] * 20 + [0.1] * 50 + [0.85] * 30
    features = extract_temporal_features(values)
    assert features.sample_count == 100
    assert features.relative_change < 0
    assert features.fade_depth > 0.8
    assert features.longest_low_run >= 40
    assert features.change_point_index > 0
    assert 0.0 <= features.recovery_ratio <= 1.0


def test_temporal_features_reject_non_finite_values():
    with pytest.raises(ValueError):
        extract_temporal_features([0.5, np.nan, 0.4])


def test_beacon_features_measure_periodicity_and_silence():
    timestamps = [0, 10, 20, 30, 40, 50, 80, 90, 100]
    features = extract_beacon_features(timestamps)
    assert features.interval_count == 8
    assert features.median_interval == 10.0
    assert features.periodicity_score < 1.0
    assert features.silence_ratio > 0.0
    assert features.longest_silence == 30.0


def test_beacon_timestamps_must_be_strictly_increasing():
    with pytest.raises(ValueError):
        extract_beacon_features([1, 1, 2])


def test_adaptive_baseline_requires_support_before_deviation_score():
    baseline = AdaptiveBaseline(decay=0.1, min_support=3)
    assert baseline.evidence(2.0).deviation_score == 0.0
    baseline.update(1.0)
    baseline.update(1.0)
    baseline.update(1.0)
    evidence = baseline.evidence(2.0)
    assert evidence.baseline_support == 3
    assert evidence.robust_zscore > 0
    assert evidence.deviation_score > 0


def test_ensemble_is_bounded_and_ml_is_secondary():
    score, components = combine_evidence(
        rule_score=0.8,
        baseline_score=0.7,
        behavioral={"sustained_drop": 0.9, "change_point": 0.8, "persistence": 0.7, "recovery": 0.5, "periodicity": 0.6},
        ml_score=1.0,
    )
    assert 0.0 <= score <= 1.0
    assert components["ml"] == 1.0
    score_without_ml, _ = combine_evidence(
        rule_score=0.8,
        baseline_score=0.7,
        behavioral={"sustained_drop": 0.9, "change_point": 0.8, "persistence": 0.7, "recovery": 0.5, "periodicity": 0.6},
    )
    assert score - score_without_ml < 0.05


def test_science_v2_exposes_explainable_evidence():
    result = detect_fade(list(range(100)), [0.9] * 20 + [0.05] * 60 + [0.9] * 20)
    assert result["detected"] is True
    assert result["science_score"] >= 0.0
    assert "temporal_features" in result
    assert "baseline_evidence" in result
    assert "beacon_features" in result
    assert result["fade_start"] > 0


def test_gradual_lotl_fade_remains_detected():
    values = [0.9 - (i * 0.008) for i in range(100)]
    result = detect_fade(list(range(100)), values)
    assert result["detected"] is True
    assert result["temporal_features"]["slope_zscore"] > 0


def test_flat_signal_does_not_gain_behavioral_detection():
    result = detect_fade(list(range(100)), [0.8] * 100)
    assert result["detected"] is False
    assert 0.0 <= result["science_score"] < 0.01
