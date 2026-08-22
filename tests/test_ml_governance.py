import numpy as np
import pytest

from core.ml_governance import ModelManifest, drift_state, manifest_digest, population_stability_index


def test_model_manifest_digest_is_deterministic():
    manifest = ModelManifest("fade-iforest", "2.0.0", "features-v2", "IsolationForest", 100, 42, "a" * 64, "2026-08-22T00:00:00Z")
    assert manifest_digest(manifest) == manifest_digest(manifest)
    assert len(manifest_digest(manifest)) == 64


def test_psi_zero_for_identical_population():
    values = np.linspace(0.0, 1.0, 100)
    assert population_stability_index(values, values) == pytest.approx(0.0, abs=1e-9)


def test_psi_increases_for_shifted_population():
    reference = np.linspace(0.0, 1.0, 100)
    shifted = np.linspace(0.5, 1.5, 100)
    psi = population_stability_index(reference, shifted)
    assert psi > 0.1
    assert drift_state(psi) in {"warning", "critical"}


def test_drift_threshold_validation():
    with pytest.raises(ValueError):
        drift_state(0.1, warning=0.3, critical=0.2)
