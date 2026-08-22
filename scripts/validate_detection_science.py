"""Deterministic architecture gate for ThreatFade Detection Science 2.0."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = (ROOT / "core" / "fade_engine.py").read_text(encoding="utf-8")
SCIENCE = (ROOT / "core" / "detection_science.py").read_text(encoding="utf-8")
CALIBRATION = (ROOT / "core" / "score_calibration.py").read_text(encoding="utf-8")
FLOW = (ROOT / "core" / "flow_features.py").read_text(encoding="utf-8")
ML_GOVERNANCE = (ROOT / "core" / "ml_governance.py").read_text(encoding="utf-8")

REQUIRED_ENGINE_MARKERS = ("science_v2", "extract_temporal_features", "extract_beacon_features", "AdaptiveBaseline", "combine_evidence", "science_score", "temporal_features", "baseline_evidence")
REQUIRED_SCIENCE_MARKERS = ("class TemporalFeatures", "class BeaconFeatures", "class AdaptiveBaseline", "def extract_temporal_features", "def extract_beacon_features", "def behavioral_evidence", "def combine_evidence")
REQUIRED_CALIBRATION_MARKERS = ("class ScoreCalibrator", "IsotonicRegression", "def freeze", "RuntimeError(\"calibrator is frozen\")")
REQUIRED_FLOW_MARKERS = ("class PacketObservation", "class ProtocolMetadata", "class FlowFeatures", "def sessionize_observations", "def activity_series", "def infer_protocol_metadata")
REQUIRED_ML_GOVERNANCE_MARKERS = ("class ModelManifest", "def artifact_sha256", "def manifest_digest", "def population_stability_index", "def drift_state")

for marker in REQUIRED_ENGINE_MARKERS:
    assert marker in ENGINE, f"fade engine missing Detection Science marker: {marker}"
for marker in REQUIRED_SCIENCE_MARKERS:
    assert marker in SCIENCE, f"detection science module missing marker: {marker}"
for marker in REQUIRED_CALIBRATION_MARKERS:
    assert marker in CALIBRATION, f"score calibration module missing marker: {marker}"
for marker in REQUIRED_FLOW_MARKERS:
    assert marker in FLOW, f"flow feature module missing marker: {marker}"
for marker in REQUIRED_ML_GOVERNANCE_MARKERS:
    assert marker in ML_GOVERNANCE, f"ML governance module missing marker: {marker}"

assert '"science_v2": True' in ENGINE
assert 'or rules_matched >= cfg["rule_threshold"]' in ENGINE
assert "not a calibrated probability" in CALIBRATION
assert 'FEATURE_SCHEMA_VERSION = "threatfade-signal-features-v2"' in ML_GOVERNANCE

print("detection science architecture: OK")
