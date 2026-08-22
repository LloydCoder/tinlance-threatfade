from benchmarks.group10_validation import make_cases, run
from benchmarks.purple_team_harness import generate_matrix, validate_matrix


def test_governed_benchmark_size_and_metrics():
    cases = make_cases(1000)
    assert len(cases) == 1000
    result = run()
    assert result["benchmark"]["cases"] == 20000
    assert 0.0 <= result["metrics"]["f1"] <= 1.0
    assert 0.0 <= result["metrics"]["false_positive_rate"] <= 1.0


def test_purple_team_matrix_complete():
    matrix = generate_matrix()
    validate_matrix(matrix)
    assert len(matrix) == 6
