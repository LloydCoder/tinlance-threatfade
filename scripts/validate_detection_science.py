"""Deterministic architecture gate for ThreatFade Detection Science 2.0."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = (ROOT / "core" / "fade_engine.py").read_text(encoding="utf-8")
SCIENCE = (ROOT / "core" / "detection_science.py").read_text(encoding="utf-8")
CALIBRATION = (ROOT / "core" / "score_calibration.py").read_text(encoding="utf-8")

REQUIRED_ENGINE_MARKERS = (
    "science_v2",
    "extract_temporal_features",
    "extract_beacon_features",
    "AdaptiveBaseline",
    "combine_evidence",
    "science_score",
    "temporal_features",
    "baseline_evidence",
)
REQUIRED_SCIENCE_MARKERS = (
    "class TemporalFeatures",
    "class BeaconFeatures",
    "class AdaptiveBaseline",
    "def extract_temporal_features",
    "def extract_beacon_features",
    "def behavioral_evidence",
    "def combine_evidence",
)
REQUIRED_CALIBRATION_MARKERS = (
    "class ScoreCalibrator",
    "IsotonicRegression",
    "def freeze",
    "RuntimeError(\"calibrator is frozen\")",
)

for marker in REQUIRED_ENGINE_MARKERS:
    assert marker in ENGINE, f"fade engine missing Detection Science marker: {marker}"
for marker in REQUIRED_SCIENCE_MARKERS:
    assert marker in SCIENCE, f"detection science module missing marker: {marker}"
for marker in REQUIRED_CALIBRATION_MARKERS:
    assert marker in CALIBRATION, f"score calibration module missing marker: {marker}"

# Ensure the new path is the default while retaining the legacy rule escape hatch.
assert '"science_v2": True' in ENGINE
assert 'or rules_matched >= cfg["rule_threshold"]' in ENGINE
# ML must remain supporting evidence rather than an implicit probability claim.
assert "not a calibrated probability" in SCIENCE

print("detection science architecture: OK")
