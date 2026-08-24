"""Reproducible synthetic validation for ThreatFade multi-domain correlation."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from core.correlation import CorrelationObservation, CorrelationPolicy, TemporalCorrelationEngine
from core.data_plane import new_event

BASE = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


def _obs(event_id: str, domain: str, signal_type: str, offset_s: float, score: float) -> CorrelationObservation:
    event = new_event("sensor-gnss" if domain == "gnss" else "sensor-network", "validation", "signal", observed_at=BASE + timedelta(seconds=offset_s))
    event = replace(event, event_id=event_id)
    return CorrelationObservation.from_event(event, domain=domain, signal_type=signal_type, signal_score=score, sensor_confidence=0.95, uncertainty=0.05)


def run() -> dict:
    policy = CorrelationPolicy(window_seconds=30, max_clock_skew_seconds=5, threshold=0.65, min_signal_score=0.5)
    engine = TemporalCorrelationEngine(policy)
    cases = [
        ("positive-001", [_obs("p1g", "gnss", "disruption", 10, 0.9), _obs("p1n", "network", "c2_fade", 14, 0.9)], True),
        ("positive-002", [_obs("p2g", "gnss", "disruption", 5, 0.8), _obs("p2n", "network", "c2_fade", 8, 0.9)], True),
        ("negative-001", [_obs("n1g", "gnss", "disruption", 0, 0.9), _obs("n1n", "network", "c2_fade", 31, 0.9)], False),
        ("negative-002", [_obs("n2g", "gnss", "disruption", 10, 0.2), _obs("n2n", "network", "c2_fade", 12, 0.9)], False),
        ("negative-003", [_obs("n3g", "gnss", "disruption", 10, 0.9)], False),
        ("negative-004", [_obs("n4n", "network", "c2_fade", 10, 0.9)], False),
    ]
    results = []
    for case_id, observations, expected in cases:
        detected = bool(engine.correlate(observations, required_domains=["gnss", "network"], generated_at=BASE))
        results.append({"case_id": case_id, "expected_detection": expected, "detected": detected})
    tp = sum(item["expected_detection"] and item["detected"] for item in results)
    fp = sum(not item["expected_detection"] and item["detected"] for item in results)
    tn = sum(not item["expected_detection"] and not item["detected"] for item in results)
    fn = sum(item["expected_detection"] and not item["detected"] for item in results)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"corpus": "TF-CORRELATION-001", "support": len(results), "true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn, "precision": precision, "recall": recall, "false_positive_rate": fpr, "cases": results}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
