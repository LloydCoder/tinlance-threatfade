"""Tests for satellite ingestor module."""
import pytest
from satellite.satellite_ingestor import (
    ingest, parse_ais, parse_adsb, parse_gps,
    simulate_ais_fade, simulate_adsb_fade, simulate_gps_jamming,
    normalize
)

def test_normalize():
    """Test normalization function."""
    values = [1.0, 2.0, 3.0]
    result = normalize(values)
    assert isinstance(result, list)
    assert len(result) == len(values)

def test_ingest_ais():
    """Test AIS data ingestion."""
    data = simulate_ais_fade(10)
    timestamps, values = ingest("ais", data)
    assert len(timestamps) == len(values)
    assert len(timestamps) > 0

def test_ingest_adsb():
    """Test ADS-B data ingestion."""
    data = simulate_adsb_fade(10)
    timestamps, values = ingest("adsb", data)
    assert len(timestamps) == len(values)
    assert len(timestamps) > 0

def test_ingest_gps():
    """Test GPS data ingestion."""
    data = simulate_gps_jamming(10)
    timestamps, values = ingest("gps", data)
    assert len(timestamps) == len(values)
    assert len(timestamps) > 0

def test_ingest_invalid_source():
    """Test invalid source type raises error."""
    with pytest.raises((ValueError, KeyError)):
        ingest("invalid", [])

def test_simulate_ais_fade():
    """Test AIS fade simulation."""
    data = simulate_ais_fade(20)
    assert len(data) == 20
    assert all(isinstance(d, dict) for d in data)

def test_simulate_adsb_fade():
    """Test ADS-B fade simulation."""
    data = simulate_adsb_fade(20)
    assert len(data) == 20
    assert all(isinstance(d, dict) for d in data)

def test_simulate_gps_jamming():
    """Test GPS jamming simulation."""
    data = simulate_gps_jamming(20)
    assert len(data) == 20
    assert all(isinstance(d, dict) for d in data)

def test_parse_ais_with_simulated_data():
    """Test AIS parsing with simulated data."""
    data = simulate_ais_fade(5)
    timestamps, values = parse_ais(data)
    assert len(timestamps) == len(values)

def test_parse_adsb_with_simulated_data():
    """Test ADS-B parsing with simulated data."""
    data = simulate_adsb_fade(5)
    timestamps, values = parse_adsb(data)
    assert len(timestamps) == len(values)

def test_parse_gps_with_simulated_data():
    """Test GPS parsing with simulated data."""
    data = simulate_gps_jamming(5)
    timestamps, values = parse_gps(data)
    assert len(timestamps) == len(values)
