"""Tests for endpoint agent functions."""
import pytest
from agents.endpoint_agent import (
    collect_network_signals, collect_process_signals,
    normalize_signals, print_agent_banner
)

def test_normalize_signals():
    """Test signal normalization."""
    signals = [10.0, 20.0, 30.0]
    result = normalize_signals(signals)
    assert isinstance(result, list)
    assert len(result) == len(signals)

def test_normalize_signals_empty():
    """Test normalization with empty list."""
    result = normalize_signals([])
    assert isinstance(result, list)
    assert len(result) == 0

def test_print_agent_banner():
    """Test banner prints without error."""
    print_agent_banner()  # Should not raise

def test_collect_network_signals_short():
    """Test network signal collection returns tuple."""
    result = collect_network_signals(duration_sec=1, interval_sec=0.5)
    assert isinstance(result, tuple)
    assert len(result) == 2

def test_collect_process_signals_short():
    """Test process signal collection returns tuple."""
    result = collect_process_signals(duration_sec=1, interval_sec=0.5)
    assert isinstance(result, tuple)
    assert len(result) == 2
