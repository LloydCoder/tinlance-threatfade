"""Tests for ThreatFade REST API (api.py)."""
import pytest
from fastapi.testclient import TestClient
from api import app

client = TestClient(app)

def test_health_endpoint():
    """Test /health returns correct structure."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["tool"] == "ThreatFade"
    assert data["version"] == "0.3.0-beta"

def test_version_endpoint():
    """Test /version returns correct structure."""
    response = client.get("/version")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "ThreatFade"

def test_detect_fade_pattern():
    """Test /detect with clear fade pattern."""
    response = client.post("/detect", json={"values": [0.9,0.9,0.05,0.05,0.05,0.9,0.9,0.9,0.9,0.9,0.9,0.9]})
    assert response.status_code == 200
    data = response.json()
    assert "detected" in data
    assert "confidence" in data

def test_detect_empty_values():
    """Test /detect with empty values returns 400."""
    response = client.post("/detect", json={"values": []})
    assert response.status_code == 400

def test_detect_scenario_c2_quieting():
    """Test /detect/scenario with c2_quieting."""
    response = client.post("/detect/scenario", json={"scenario": "c2_quieting"})
    assert response.status_code == 200
    data = response.json()
    assert data["detected"] == True

def test_detect_scenario_lotl_gradual():
    """Test /detect/scenario with lotl_gradual."""
    response = client.post("/detect/scenario", json={"scenario": "lotl_gradual"})
    assert response.status_code == 200
    data = response.json()
    assert data["detected"] == True

def test_detect_scenario_gnss_jam():
    """Test /detect/scenario with gnss_jam."""
    response = client.post("/detect/scenario", json={"scenario": "gnss_jam"})
    assert response.status_code == 200
    data = response.json()
    assert data["detected"] == True

def test_detect_scenario_mixed():
    """Test /detect/scenario with mixed."""
    response = client.post("/detect/scenario", json={"scenario": "mixed"})
    assert response.status_code == 200
    data = response.json()
    assert data["detected"] == True

def test_detect_scenario_normal_with_fade():
    """Test /detect/scenario with normal_with_fade."""
    response = client.post("/detect/scenario", json={"scenario": "normal_with_fade"})
    assert response.status_code == 200
    data = response.json()
    assert "detected" in data

def test_detect_scenario_invalid():
    """Test /detect/scenario with invalid scenario returns 400."""
    response = client.post("/detect/scenario", json={"scenario": "invalid_scenario"})
    assert response.status_code == 400

def test_detect_pcap_no_file():
    """Test /detect/pcap without file returns 422."""
    response = client.post("/detect/pcap")
    assert response.status_code == 422

def test_docs_endpoint():
    """Test /docs is accessible."""
    response = client.get("/docs")
    assert response.status_code == 200
