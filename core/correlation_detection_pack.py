"""Versioned detection-pack definitions for multi-domain correlation."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .detection_pack import DetectionRule


CORRELATION_RULE = DetectionRule(
    "TF-CORR-001",
    "1.0.0",
    "Multi-domain temporal corroboration",
    "Correlates independent signal domains within an explicit temporal window; establishes observed correlation, not causal attribution.",
    ["T1071", "T1562"],
)

GNSS_NETWORK_RULE = DetectionRule(
    "TF-GNSS-CORR-001",
    "1.0.0",
    "GNSS disruption with network fade correlation",
    "Correlates a GNSS disruption observation with a network fade/C2 observation while preserving uncertainty and temporal provenance.",
    ["T1071", "T1562"],
)


def correlation_detection_pack() -> dict[str, Any]:
    """Return the generic reusable correlation pack."""
    return {
        "name": "ThreatFade Multi-Domain Correlation Pack",
        "version": "1.0.0",
        "rules": [asdict(CORRELATION_RULE)],
        "correlation_policy": {
            "window_seconds": 30.0,
            "max_clock_skew_seconds": 5.0,
            "threshold": 0.65,
            "min_signal_score": 0.50,
            "causal_attribution": "not_established",
        },
    }


def gnss_network_correlation_pack() -> dict[str, Any]:
    """Return the first concrete deployment of the reusable correlation model."""
    return {
        "name": "ThreatFade GNSS Network Correlation Pack",
        "version": "1.0.0",
        "rules": [asdict(GNSS_NETWORK_RULE)],
        "required_domains": ["gnss", "network"],
        "accepted_signal_types": {
            "gnss": ["disruption", "integrity_degradation", "signal_loss"],
            "network": ["fade", "c2_fade", "beacon_silence"],
        },
        "correlation_policy": {
            "window_seconds": 30.0,
            "max_clock_skew_seconds": 5.0,
            "threshold": 0.65,
            "min_signal_score": 0.50,
            "causal_attribution": "not_established",
        },
        "evidence_boundary": "The result is an observed temporal correlation. It does not establish that GNSS interference caused the network behavior or that either observation was malicious.",
    }
