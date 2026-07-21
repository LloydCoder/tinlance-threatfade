"""Tests for parallel PCAP processor."""
import pytest
import os
from core.pcap_parallel_processor import (
    extract_packet_features,
    process_chunk,
    process_pcap_parallel
)


def test_extract_packet_features():
    """Test feature extraction with mock packet."""
    class MockPkt:
        def __contains__(self, item):
            return False
    result = extract_packet_features(MockPkt())
    assert isinstance(result, float)
    assert result == 0.0


def test_process_chunk_empty():
    """Test processing empty chunk."""
    result = process_chunk((0, []))
    assert result["detected"] == False
    assert result["chunk_id"] == 0


def test_process_chunk_small():
    """Test processing small chunk (too small for detection)."""
    result = process_chunk((1, [0.1, 0.2, 0.3]))
    assert result["chunk_id"] == 1
    # Small chunks may not have packet_count if detection skipped
    assert "chunk_id" in result


def test_process_chunk_normal():
    """Test processing normal chunk with fade pattern."""
    features = [0.9] * 50 + [0.1] * 50 + [0.9] * 50
    result = process_chunk((2, features))
    assert result["chunk_id"] == 2
    assert "detected" in result


@pytest.mark.skipif(not os.path.exists("pcaps/icedid.pcap"), reason="No PCAP")
def test_process_pcap_parallel_icedid():
    """Test parallel processing on IcedID PCAP."""
    result = process_pcap_parallel("pcaps/icedid.pcap", chunk_size=5000, max_workers=2)
    assert result["total_packets"] > 0
    assert result["parallel_workers"] == 2


@pytest.mark.skipif(not os.path.exists("pcaps/cobalt_strike.pcap"), reason="No PCAP")
def test_process_pcap_parallel_cobalt_strike():
    """Test parallel processing on Cobalt Strike PCAP."""
    result = process_pcap_parallel("pcaps/cobalt_strike.pcap", chunk_size=5000, max_workers=2)
    assert result["total_packets"] > 0
