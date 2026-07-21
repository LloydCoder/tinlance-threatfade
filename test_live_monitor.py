"""Tests for LiveMonitor module."""
import pytest
from core.live_monitor import LiveMonitor, is_live_available

def test_is_live_available():
    """Test live monitoring availability check."""
    result = is_live_available()
    assert isinstance(result, bool)

def test_live_monitor_init():
    """Test LiveMonitor initializes correctly."""
    monitor = LiveMonitor(interface="lo")
    assert monitor.interface == "lo"
    assert monitor.running == False

def test_live_monitor_running_state():
    """Test running state."""
    monitor = LiveMonitor(interface="lo")
    assert monitor.running == False

def test_live_monitor_packet_buffer():
    """Test packet buffer exists."""
    monitor = LiveMonitor(interface="lo")
    assert hasattr(monitor, 'packet_buffer')

def test_live_monitor_lock():
    """Test lock exists."""
    monitor = LiveMonitor(interface="lo")
    assert hasattr(monitor, '_lock')
