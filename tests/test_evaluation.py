import math

import pytest

from core.evaluation import EvaluationCase, bootstrap_confidence_interval, evaluate_cases


def test_evaluation_reports_confusion_matrix_and_classification_metrics():
    cases = [
        EvaluationCase("tp-1", "c2_quieting", True, True),
        EvaluationCase("tp-2", "lotl_gradual", True, True),
        EvaluationCase("fn-1", "gnss_jam", True, False),
        EvaluationCase("tn-1", "normal", False, False),
        EvaluationCase("fp-1", "normal", False, True),
    ]

    report = evaluate_cases(cases, bootstrap=False)
    metrics = report["metrics"]

    assert metrics["true_positive"] == 2
    assert metrics["false_positive"] == 1
    assert metrics["true_negative"] == 1
    assert metrics["false_negative"] == 1
    assert metrics["precision"] == pytest.approx(2 / 3)
    assert metrics["recall"] == pytest.approx(2 / 3)
    assert metrics["f1"] == pytest.approx(2 / 3)
    assert metrics["false_positive_rate"] == pytest.approx(0.5)
    assert metrics["false_negative_rate"] == pytest.approx(1 / 3)


def test_bootstrap_interval_is_deterministic_and_bounded():
    cases = [
        EvaluationCase(str(i), "scenario", i % 2 == 0, i not in {1, 6})
        for i in range(10)
    ]
    first = bootstrap_confidence_interval(cases, metric="f1", iterations=500, seed=42)
    second = bootstrap_confidence_interval(cases, metric="f1", iterations=500, seed=42)

    assert first == second
    assert 0.0 <= first["lower"] <= first["estimate"] <= first["upper"] <= 1.0
    assert first["iterations"] == 500


def test_latency_summary_reports_percentiles():
    cases = [
        EvaluationCase("1", "a", True, True, latency_ms=1.0),
        EvaluationCase("2", "a", True, True, latency_ms=2.0),
        EvaluationCase("3", "b", False, False, latency_ms=10.0),
    ]
    report = evaluate_cases(cases, bootstrap=False)
    latency = report["latency"]
    assert latency["count"] == 3
    assert latency["p50_ms"] == pytest.approx(2.0)
    assert latency["p95_ms"] > latency["p50_ms"]
    assert math.isfinite(latency["p99_ms"])


def test_empty_evaluation_is_safe():
    report = evaluate_cases([], bootstrap=True)
    assert report["corpus_size"] == 0
    assert report["metrics"]["accuracy"] == 0.0
    assert report["confidence_intervals"] == {}
