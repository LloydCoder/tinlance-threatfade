import numpy as np
import pytest

from core.ml_experiments import (
    DatasetManifest,
    evaluate_baseline,
    evaluate_isolation_forest,
    promotion_gate,
    time_ordered_split,
)


def corpus():
    rng = np.random.default_rng(42)
    benign = rng.normal(0, 1, size=(40, 8))
    attacks = rng.normal(3.5, 0.8, size=(20, 8))
    X = np.vstack([benign, attacks])
    y = np.array([0] * 40 + [1] * 20)
    return X, y


def test_time_ordered_split_is_deterministic_and_non_leaky():
    X, y = corpus()
    a = time_ordered_split(X, y)
    b = time_ordered_split(X, y)
    for left, right in zip(a, b):
        assert np.array_equal(left, right)
    assert a[0][-1, 0] != a[1][0, 0]


def test_manifest_digest_is_stable():
    manifest = DatasetManifest("fixture", "1", "deterministic-test")
    assert manifest.digest() == manifest.digest()
    assert len(manifest.digest()) == 64


def test_baseline_evaluation_is_reproducible():
    X, y = corpus()
    manifest = DatasetManifest("fixture", "1", "deterministic-test")
    result = evaluate_baseline(X, y, manifest)
    assert 0.0 <= result.roc_auc <= 1.0
    assert 0.0 <= result.average_precision <= 1.0
    assert result.explainable is True


def test_isolation_forest_never_trains_on_test_attacks():
    pytest.importorskip("sklearn")
    X, y = corpus()
    manifest = DatasetManifest("fixture", "1", "deterministic-test")
    result = evaluate_isolation_forest(X, y, manifest)
    assert result.model_id == "isolation-forest-experimental"
    assert result.production_candidate is False


def test_promotion_gate_requires_all_governance_properties():
    X, y = corpus()
    manifest = DatasetManifest("fixture", "1", "deterministic-test")
    baseline = evaluate_baseline(X, y, manifest)
    candidate = baseline
    gated = promotion_gate(candidate, baseline)
    assert gated.production_candidate is False
    assert "AP delta" in gated.rationale
