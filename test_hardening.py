import json
from pathlib import Path

import numpy as np

from core.detection_pack import detection_pack, validate_pack
from core.explainability import build_evidence
from core.interoperability import to_sigma, to_stix_bundle
from core.volatility_adapter import analyze_memory


def test_detection_pack_is_versioned():
    pack = detection_pack()
    validate_pack(pack)
    assert pack["version"]
    assert len(pack["rules"]) >= 3


def test_explainability_contains_evidence():
    evidence = build_evidence({"score": 0.8, "drop_ratio": 0.7, "z_outlier": 7, "rules_matched": 2})
    assert evidence["signals"]
    assert evidence["metrics"]["z_outlier"] == 7


def test_sigma_export_shape():
    sigma = to_sigma({"confidence": "high", "detected": True})
    assert sigma["detection"]["condition"] == "selection"
    assert sigma["status"] == "experimental"


def test_stix_bundle_shape():
    bundle = to_stix_bundle({"score": 0.9, "confidence": "high"})
    assert bundle["type"] == "bundle"
    assert all(obj["spec_version"] == "2.1" for obj in bundle["objects"])


def test_memory_adapter_rejects_missing_image():
    try:
        analyze_memory("/definitely/not/a/memory/image")
    except FileNotFoundError:
        return
    raise AssertionError("missing memory image must be rejected")


def test_adversarial_jitter_does_not_crash():
    from core.fade_engine import detect_fade
    rng = np.random.default_rng(42)
    values = [float(np.clip(0.8 + rng.normal(0, 0.15), 0, 1)) for _ in range(100)]
    values[45:65] = [float(np.clip(v * 0.15, 0, 1)) for v in values[45:65]]
    result = detect_fade(list(range(100)), values)
    assert isinstance(result["detected"], bool)
    assert 0.0 <= result["score"] <= 1.0


def test_constant_signal_is_stable():
    from core.fade_engine import detect_fade
    result = detect_fade(list(range(100)), [0.75] * 100)
    assert result["detected"] is False
    assert result["z_outlier"] == 0.0
