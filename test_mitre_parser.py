"""Tests for MITRE rule parser."""
import pytest
from mitre.rule_parser import match_mitre_ttp, match_all_ttps, get_mitre_description, get_mitre_tactic

@pytest.fixture
def sample_result():
    return {
        "detected": True,
        "confidence": "high",
        "score": 0.85,
        "entropy": 2.5,
        "drop_ratio": 0.75,
        "z_outlier": 2.8
    }

def test_match_mitre_ttp_returns_string(sample_result):
    """Test match_mitre_ttp returns a string."""
    result = match_mitre_ttp(sample_result)
    assert isinstance(result, str)

def test_match_mitre_ttp_contains_ttp_id(sample_result):
    """Test result contains TTP ID."""
    result = match_mitre_ttp(sample_result)
    assert "T" in result

def test_match_all_ttps_returns_list(sample_result):
    """Test match_all_ttps returns a list."""
    results = match_all_ttps(sample_result)
    assert isinstance(results, list)

def test_match_all_ttps_contains_dicts(sample_result):
    """Test match_all_ttps returns list of dicts."""
    results = match_all_ttps(sample_result)
    if len(results) > 0:
        assert isinstance(results[0], dict)

def test_get_mitre_description_known_ttp():
    """Test description for known TTP."""
    desc = get_mitre_description("T1573.002")
    assert isinstance(desc, str)
    assert len(desc) > 0

def test_get_mitre_description_unknown_ttp():
    """Test description for unknown TTP."""
    desc = get_mitre_description("T9999.999")
    assert isinstance(desc, str)

def test_get_mitre_tactic_known_ttp():
    """Test tactic for known TTP."""
    tactic = get_mitre_tactic("T1573.002")
    assert isinstance(tactic, str)
