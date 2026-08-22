import pytest

from core.flow_features import (
    PacketObservation,
    activity_series,
    extract_flow_features,
    infer_protocol_metadata,
    sessionize_observations,
)


def packet(t, src="10.0.0.1", dst="10.0.0.2", sport=50000, dport=443, size=1000, protocol="TCP"):
    return PacketObservation(t, src, dst, sport, dport, protocol, size, size - 100)


def test_bidirectional_flow_key_is_stable():
    forward = packet(1.0)
    reverse = packet(2.0, src="10.0.0.2", dst="10.0.0.1", sport=443, dport=50000)
    assert forward.bidirectional_key == reverse.bidirectional_key


def test_sessionize_splits_on_inactivity_gap():
    observations = [packet(0), packet(1), packet(2), packet(40)]
    sessions = sessionize_observations(observations, inactivity_gap_seconds=10)
    assert [len(session) for session in sessions] == [3, 1]


def test_flow_features_are_deterministic():
    features = extract_flow_features([packet(0), packet(1), packet(2)])
    assert features.packet_count == 3
    assert features.total_bytes == 3000
    assert features.payload_bytes == 2700
    assert features.duration_seconds == 2.0
    assert features.mean_interarrival_seconds == 1.0
    assert features.packets_per_second == 1.5
    assert features.bytes_per_second == 1500.0
    assert features.application_protocol == "TLS"
    assert features.encrypted_transport is True


def test_quic_metadata_is_encrypted():
    metadata = infer_protocol_metadata(packet(0, sport=40000, dport=443, protocol="UDP"))
    assert metadata.application_protocol == "QUIC"
    assert metadata.encrypted_transport is True


def test_activity_series_is_dense_and_normalized():
    timestamps, values = activity_series([packet(0, size=500), packet(1, size=1000), packet(3, size=250)], interval_seconds=1)
    assert timestamps == [0.0, 1.0, 2.0, 3.0]
    assert values[1] == 1.0
    assert len(values) == 4
    assert max(values) == 1.0


def test_invalid_packet_sizes_are_rejected():
    with pytest.raises(ValueError):
        PacketObservation(1.0, "a", "b", 1, 2, "TCP", 10, 11)
