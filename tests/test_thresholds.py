import pytest

from core.evaluation import EvaluationCase
from core.thresholds import calibrate_threshold


def test_youden_calibration_is_reproducible():
    cases = [
        EvaluationCase("p1", "malicious", True, True, score=0.9),
        EvaluationCase("p2", "malicious", True, True, score=0.8),
        EvaluationCase("n1", "benign", False, False, score=0.2),
        EvaluationCase("n2", "benign", False, False, score=0.1),
    ]
    result = calibrate_threshold(cases)
    assert result.threshold == pytest.approx(0.8)
    assert result.true_positive == 2
    assert result.false_positive == 0


def test_constrained_calibration_respects_false_positive_rate():
    cases = [
        EvaluationCase("p1", "malicious", True, True, score=0.9),
        EvaluationCase("p2", "malicious", True, True, score=0.6),
        EvaluationCase("n1", "benign", False, False, score=0.5),
        EvaluationCase("n2", "benign", False, False, score=0.2),
    ]
    result = calibrate_threshold(cases, objective="constrained_recall", max_false_positive_rate=0.0)
    assert result.threshold >= 0.6
    assert result.false_positive == 0


def test_constrained_calibration_requires_constraint():
    with pytest.raises(ValueError, match="required"):
        calibrate_threshold([EvaluationCase("x", "x", True, True, score=0.5)], objective="constrained_recall")
