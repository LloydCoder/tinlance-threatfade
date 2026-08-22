from benchmarks.benchmark import RUNS_PER_SCENARIO, SCENARIOS, run


def test_synthetic_evaluation_corpus_shape_and_quality():
    report = run()

    assert report["benchmark"] == "synthetic-scenario-v2"
    assert report["corpus_size"] == len(SCENARIOS) * RUNS_PER_SCENARIO
    assert report["metrics"]["recall"] == 1.0
    assert report["metrics"]["false_positive_rate"] == 0.0
    assert report["metrics"]["false_negative_rate"] == 0.0
    assert report["scenarios"]["normal_with_fade"]["false_positive_rate"] == 0.0
    assert set(report["confidence_intervals"]) == {"precision", "recall", "f1", "false_positive_rate"}
