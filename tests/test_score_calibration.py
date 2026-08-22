import numpy as np
import pytest

from core.score_calibration import ScoreCalibrator


def test_isotonic_calibration_fits_and_freezes():
    calibrator = ScoreCalibrator()
    report = calibrator.fit(
        [0.05, 0.10, 0.20, 0.30, 0.55, 0.70, 0.80, 0.95],
        [False, False, False, False, True, True, True, True],
    )
    assert report.method == "isotonic_regression"
    assert report.tuning_support == 8
    assert report.frozen is False
    calibrator.freeze()
    assert calibrator.frozen is True
    transformed = calibrator.transform([0.15, 0.75])
    assert np.all((transformed >= 0.0) & (transformed <= 1.0))
    assert transformed[1] >= transformed[0]


def test_frozen_calibrator_cannot_be_refit():
    calibrator = ScoreCalibrator()
    calibrator.fit([0.1, 0.2, 0.8, 0.9], [False, False, True, True])
    calibrator.freeze()
    with pytest.raises(RuntimeError):
        calibrator.fit([0.1, 0.2, 0.8, 0.9], [False, False, True, True])


def test_calibration_requires_both_classes():
    with pytest.raises(ValueError):
        ScoreCalibrator().fit([0.1, 0.2, 0.3, 0.4], [False, False, False, False])


def test_calibration_rejects_non_finite_scores():
    with pytest.raises(ValueError):
        ScoreCalibrator().fit([0.1, np.nan, 0.8, 0.9], [False, False, True, True])
