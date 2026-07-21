"""Tests for MLDetector module."""
import pytest
import numpy as np
from core.ml_stub import MLDetector, is_ml_available, extract_features

@pytest.fixture
def detector():
    return MLDetector()

def test_is_ml_available():
    """Test ML availability check."""
    result = is_ml_available()
    assert isinstance(result, bool)

def test_extract_features():
    """Test feature extraction returns numpy array."""
    features = extract_features([0.5, 0.6, 0.7])
    assert isinstance(features, (np.ndarray, list))
    assert len(features) > 0

def test_ml_detector_init(detector):
    """Test MLDetector initializes correctly."""
    assert detector is not None

def test_ml_detector_predict_normal(detector):
    """Test prediction on normal traffic returns tuple."""
    result = detector.predict([0.6, 0.65, 0.7, 0.68, 0.72])
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert isinstance(result[0], (int, float))
    assert isinstance(result[1], bool)

def test_ml_detector_predict_anomaly(detector):
    """Test prediction on anomalous traffic returns tuple."""
    result = detector.predict([0.9, 0.05, 0.9, 0.05, 0.9])
    assert isinstance(result, tuple)
    assert len(result) == 2

def test_ml_detector_predict_single_value(detector):
    """Test prediction with single value returns tuple."""
    result = detector.predict([0.5])
    assert isinstance(result, tuple)
    assert len(result) == 2

def test_ml_detector_predict_empty(detector):
    """Test prediction with empty input returns tuple."""
    result = detector.predict([])
    assert isinstance(result, tuple)
    assert len(result) == 2

def test_ml_detector_trained_attribute(detector):
    """Test trained attribute exists."""
    assert hasattr(detector, 'trained')
    assert isinstance(detector.trained, bool)
