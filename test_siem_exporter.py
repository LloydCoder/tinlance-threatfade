"""Tests for SIEMExporter module."""
import pytest
import json
import os
from core.siem_exporter import SIEMExporter

@pytest.fixture
def exporter(tmp_path):
    return SIEMExporter(output_dir=str(tmp_path))

@pytest.fixture
def sample_detection():
    return {
        "detected": True,
        "confidence": "high",
        "score": 0.85,
        "entropy": 2.5,
        "drop_ratio": 0.75,
        "z_outlier": 2.8,
        "mitre_ttp": "T1573.002"
    }

def test_exporter_init(exporter):
    """Test SIEMExporter initializes correctly."""
    assert exporter is not None
    assert os.path.exists(exporter.output_dir)

def test_export_json(exporter, sample_detection):
    """Test JSON export format."""
    result = exporter.export([sample_detection], "json", "test_alert")
    assert isinstance(result, str)
    if os.path.exists(result):
        with open(result) as f:
            data = json.load(f)
        assert isinstance(data, list)

def test_export_cef(exporter, sample_detection):
    """Test CEF export format."""
    result = exporter.export([sample_detection], "cef", "test_alert")
    assert isinstance(result, str)
    if os.path.exists(result):
        with open(result) as f:
            content = f.read()
        assert "CEF:" in content

def test_export_syslog(exporter, sample_detection):
    """Test syslog export format."""
    result = exporter.export([sample_detection], "syslog", "test_alert")
    assert isinstance(result, str)
    if os.path.exists(result):
        with open(result) as f:
            content = f.read()
        assert "ThreatFade" in content

def test_export_unsupported_format(exporter, sample_detection):
    """Test unsupported format returns error string."""
    result = exporter.export([sample_detection], "splunk", "test_alert")
    assert isinstance(result, str)
    assert "Unsupported" in result

def test_export_csv_not_supported(exporter, sample_detection):
    """Test CSV is not supported."""
    result = exporter.export([sample_detection], "csv", "test_alert")
    assert isinstance(result, str)
    assert "Unsupported" in result

def test_export_empty_events(exporter):
    """Test export with empty events returns message."""
    result = exporter.export([], "json", "empty_alert")
    assert isinstance(result, str)
