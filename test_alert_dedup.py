"""Tests for AlertDeduplicator module."""
import pytest
import time
from core.alert_dedup import AlertDeduplicator

@pytest.fixture
def dedup():
    return AlertDeduplicator(window_sec=60, max_cache=100)

def test_alert_dedup_init(dedup):
    """Test AlertDeduplicator initializes correctly."""
    assert dedup.window_sec == 60
    assert dedup.max_cache == 100

def test_dedup_empty_result(dedup):
    """Test deduplication with empty result."""
    result = {}
    is_dup = dedup.is_duplicate(result, "T1573.002")
    assert is_dup == False

def test_dedup_same_alert_twice(dedup):
    """Test same alert is deduplicated."""
    result = {"detected": True, "score": 0.85}
    assert dedup.is_duplicate(result, "T1573.002") == False
    assert dedup.is_duplicate(result, "T1573.002") == True

def test_dedup_different_mitre_ttp(dedup):
    """Test different MITRE TTPs are not deduplicated."""
    result = {"detected": True, "score": 0.85}
    assert dedup.is_duplicate(result, "T1573.002") == False
    assert dedup.is_duplicate(result, "T1071.004") == False

def test_dedup_cache_size(dedup):
    """Test cache size tracking."""
    result = {"detected": True, "score": 0.85}
    dedup.is_duplicate(result, "T1573.002")
    assert dedup.cache_size() >= 1

def test_dedup_window_expiry(dedup):
    """Test deduplication window expiry."""
    dedup_short = AlertDeduplicator(window_sec=0, max_cache=100)
    result = {"detected": True, "score": 0.85}
    dedup_short.is_duplicate(result, "T1573.002")
    time.sleep(0.1)
    assert dedup_short.is_duplicate(result, "T1573.002") == False

def test_dedup_cache_eviction(dedup):
    """Test cache eviction when max_cache reached."""
    for i in range(110):
        dedup.is_duplicate({"detected": True, "score": i * 0.01}, f"T1000.{i:03d}")
    assert dedup.cache_size() <= 100
