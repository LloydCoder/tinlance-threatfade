from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from core.correlation import (
    CorrelationObservation,
    CorrelationPolicy,
    TemporalCorrelationEngine,
    evidence_custody_record,
)
from core.data_plane import new_event


BASE = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


def observation(event_id: str, *, domain: str, signal_type: str, seconds: float, score: float = 0.9, sensor_confidence: float = 0.95, uncertainty: float = 0.05):
    event = new_event(
        "sensor-1" if domain == "network" else "sensor-2",
        "tenant-a",
        "signal",
        observed_at=BASE + timedelta(seconds=seconds),
        metadata={"domain": domain, "signal_type": signal_type},
    )
    event = replace(event, event_id=event_id)
    return CorrelationObservation.from_event(
        event,
        domain=domain,
        signal_type=signal_type,
        signal_score=score,
        sensor_confidence=sensor_confidence,
        uncertainty=uncertainty,
    )


def test_gnss_network_correlation_is_deterministic_and_non_causal():
    gnss = observation("gnss-1", domain="gnss", signal_type="disruption", seconds=10)
    network = observation("network-1", domain="network", signal_type="c2_fade", seconds=15)
    engine = TemporalCorrelationEngine()

    first = engine.correlate([network, gnss], required_domains=["gnss", "network"], generated_at=BASE)
    second = engine.correlate([gnss, network], required_domains=["gnss", "network"], generated_at=BASE)

    assert len(first) == 1
    assert first[0].canonical_dict() == second[0].canonical_dict()
    assert first[0].attribution == "observed_correlation"
    assert first[0].causal_attribution == "not_established"
    assert first[0].temporal_delta_ms == 5000


def test_outside_window_does_not_correlate():
    gnss = observation("gnss-1", domain="gnss", signal_type="disruption", seconds=0)
    network = observation("network-1", domain="network", signal_type="c2_fade", seconds=31)
    assert TemporalCorrelationEngine().correlate([gnss, network], required_domains=["gnss", "network"]) == []


def test_clock_skew_is_explicitly_reported():
    gnss = observation("gnss-1", domain="gnss", signal_type="disruption", seconds=10)
    network = observation("network-1", domain="network", signal_type="c2_fade", seconds=14)
    result = TemporalCorrelationEngine().correlate([gnss, network], required_domains=["gnss", "network"])
    assert result[0].clock_skew_tolerance_ms == 5000


def test_duplicate_events_do_not_increase_confidence():
    gnss = observation("gnss-1", domain="gnss", signal_type="disruption", seconds=10)
    network = observation("network-1", domain="network", signal_type="c2_fade", seconds=12)
    result = TemporalCorrelationEngine().correlate([gnss, network, network], required_domains=["gnss", "network"])
    assert len(result) == 1
    assert result[0].duplicate_event_ids == (network.event_id,)


def test_out_of_order_input_is_normalized_and_recorded():
    first = observation("gnss-1", domain="gnss", signal_type="disruption", seconds=20)
    second = observation("network-1", domain="network", signal_type="c2_fade", seconds=10)
    result = TemporalCorrelationEngine().correlate([first, second], required_domains=["gnss", "network"])
    assert len(result) == 1
    assert result[0].out_of_order_count == 1


def test_low_signal_or_missing_domain_fails_closed():
    weak = observation("gnss-1", domain="gnss", signal_type="disruption", seconds=10, score=0.2)
    network = observation("network-1", domain="network", signal_type="c2_fade", seconds=12)
    assert TemporalCorrelationEngine().correlate([weak, network], required_domains=["gnss", "network"]) == []


def test_tenant_isolation_prevents_cross_tenant_correlation():
    gnss = observation("gnss-1", domain="gnss", signal_type="disruption", seconds=10)
    event = new_event("sensor-3", "tenant-b", "signal", observed_at=BASE + timedelta(seconds=12))
    network = CorrelationObservation.from_event(event, domain="network", signal_type="c2_fade", signal_score=0.9)
    assert TemporalCorrelationEngine().correlate([gnss, network], required_domains=["gnss", "network"]) == []


def test_uncertain_observation_reduces_confidence():
    gnss = observation("gnss-1", domain="gnss", signal_type="disruption", seconds=10, uncertainty=1.0)
    network = observation("network-1", domain="network", signal_type="c2_fade", seconds=12)
    assert TemporalCorrelationEngine().correlate([gnss, network], required_domains=["gnss", "network"]) == []


def test_evidence_custody_is_verifiable_and_tenant_bound():
    gnss = observation("gnss-1", domain="gnss", signal_type="disruption", seconds=10)
    network = observation("network-1", domain="network", signal_type="c2_fade", seconds=12)
    result = TemporalCorrelationEngine().correlate([gnss, network], required_domains=["gnss", "network"], generated_at=BASE)[0]
    record = evidence_custody_record(result)
    assert record["tenant_id"] == "tenant-a"
    assert len(record["content_sha256"]) == 64
    assert len(record["custody_hash"]) == 64
    assert record["causal_attribution"] == "not_established"


def test_policy_rejects_invalid_clock_skew():
    with pytest.raises(ValueError):
        CorrelationPolicy(window_seconds=5, max_clock_skew_seconds=6)
