"""Tests for ThreatFade REST API (api.py)."""
import pytest
from fastapi.testclient import TestClient
from api import app

@pytest.fixture
def client():
    return TestClient(app)

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["tool"] == "ThreatFade"

def test_version_endpoint(client):
    response = client.get("/version")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "ThreatFade"

def test_detect_fade_pattern(client):
    response = client.post("/detect", json={"values": [0.9,0.9,0.05,0.05,0.05,0.9,0.9,0.9,0.9,0.9,0.9,0.9]})
    assert response.status_code == 200
    data = response.json()
    assert "detected" in data

def test_detect_empty_values(client):
    response = client.post("/detect", json={"values": []})
    assert response.status_code == 400

def test_detect_scenario_c2_quieting(client):
    response = client.post("/detect/scenario", json={"scenario": "c2_quieting"})
    assert response.status_code == 200
    data = response.json()
    assert data["detected"] == True

def test_detect_scenario_invalid(client):
    response = client.post("/detect/scenario", json={"scenario": "invalid"})
    assert response.status_code == 400

def test_detect_pcap_no_file(client):
    response = client.post("/detect/pcap")
    assert response.status_code == 422

def test_docs_endpoint(client):
    response = client.get("/docs")
    assert response.status_code == 200
