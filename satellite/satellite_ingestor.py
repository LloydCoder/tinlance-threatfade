"""
ThreatFade Satellite Signal Ingestor
Accepts AIS (ship tracking), ADS-B (aircraft), and GPS telemetry.
Converts satellite telemetry into entropy signals for fade detection.

Supported formats:
    AIS  - Automatic Identification System (maritime)
    ADS-B - Automatic Dependent Surveillance-Broadcast (aviation)
    GPS  - Generic GPS telemetry (ground/sovereign assets)

Usage:
    python satellite/satellite_ingestor.py --type ais --file ais_feed.json
    python satellite/satellite_ingestor.py --type adbs --file adbs_feed.json
    python satellite/satellite_ingestor.py --simulate --type ais --duration 120
"""

import json
import math
import random
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple, Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Signal normalization ──────────────────────────────────────

def normalize(values: List[float]) -> List[float]:
    if not values:
        return []
    mn, mx = min(values), max(values)
    if mx == mn:
        return [0.5] * len(values)
    return [(v - mn) / (mx - mn) for v in values]


# ── AIS Parser ────────────────────────────────────────────────

def parse_ais(data: List[Dict]) -> Tuple[List[float], List[float]]:
    """
    Parse AIS maritime tracking data.
    Signal = vessel speed (knots) — fade = vessel going silent/stopped.
    
    Expected format:
    [{"timestamp": "...", "mmsi": "...", "speed": 12.3, "status": "..."}]
    """
    timestamps, values = [], []
    for entry in sorted(data, key=lambda x: x.get("timestamp", "")):
        try:
            ts = datetime.fromisoformat(entry["timestamp"]).timestamp()
            speed = float(entry.get("speed", 0))
            timestamps.append(ts)
            values.append(speed)
        except (KeyError, ValueError):
            continue
    return timestamps, normalize(values)


# ── ADS-B Parser ──────────────────────────────────────────────

def parse_adsb(data: List[Dict]) -> Tuple[List[float], List[float]]:
    """
    Parse ADS-B aviation tracking data.
    Signal = altitude (ft) — fade = aircraft going dark/transponder off.
    
    Expected format:
    [{"timestamp": "...", "icao": "...", "altitude": 35000, "speed": 450}]
    """
    timestamps, values = [], []
    for entry in sorted(data, key=lambda x: x.get("timestamp", "")):
        try:
            ts = datetime.fromisoformat(entry["timestamp"]).timestamp()
            alt = float(entry.get("altitude", 0))
            timestamps.append(ts)
            values.append(alt)
        except (KeyError, ValueError):
            continue
    return timestamps, normalize(values)


# ── GPS Parser ────────────────────────────────────────────────

def parse_gps(data: List[Dict]) -> Tuple[List[float], List[float]]:
    """
    Parse generic GPS telemetry.
    Signal = signal strength (dBm) — fade = GNSS jamming/spoofing.
    
    Expected format:
    [{"timestamp": "...", "lat": 6.5, "lon": 3.3, "signal_strength": -85}]
    """
    timestamps, values = [], []
    for entry in sorted(data, key=lambda x: x.get("timestamp", "")):
        try:
            ts = datetime.fromisoformat(entry["timestamp"]).timestamp()
            strength = float(entry.get("signal_strength", -100))
            # Convert dBm to 0-1 scale (-120 dBm = 0, -60 dBm = 1)
            normalized = max(0.0, min(1.0, (strength + 120) / 60))
            timestamps.append(ts)
            values.append(normalized)
        except (KeyError, ValueError):
            continue
    return timestamps, values


# ── Simulator ─────────────────────────────────────────────────

def simulate_ais_fade(num_points: int = 100) -> List[Dict]:
    """Simulate AIS vessel going dark (C2 evasion at sea)."""
    now = datetime.now()
    data = []
    for i in range(num_points):
        ts = now + timedelta(minutes=i * 5)
        if 30 <= i <= 70:
            speed = random.uniform(0, 0.5)  # vessel going dark
        else:
            speed = random.uniform(10, 20)  # normal vessel speed
        data.append({
            "timestamp": ts.isoformat(),
            "mmsi": "123456789",
            "speed": round(speed, 2),
            "status": "under_way" if speed > 1 else "silent",
        })
    return data


def simulate_adsb_fade(num_points: int = 100) -> List[Dict]:
    """Simulate aircraft transponder going dark (ADS-B fade)."""
    now = datetime.now()
    data = []
    for i in range(num_points):
        ts = now + timedelta(minutes=i * 2)
        if 40 <= i <= 75:
            alt = random.uniform(0, 1000)  # transponder off / low
        else:
            alt = random.uniform(30000, 40000)  # cruise altitude
        data.append({
            "timestamp": ts.isoformat(),
            "icao": "A1B2C3",
            "altitude": round(alt),
            "speed": random.uniform(400, 500) if alt > 5000 else 0,
        })
    return data


def simulate_gps_jamming(num_points: int = 100) -> List[Dict]:
    """Simulate GNSS jamming event."""
    now = datetime.now()
    data = []
    for i in range(num_points):
        ts = now + timedelta(seconds=i * 30)
        if 25 <= i <= 65:
            strength = random.uniform(-120, -110)  # jammed signal
        else:
            strength = random.uniform(-75, -65)  # normal GPS
        data.append({
            "timestamp": ts.isoformat(),
            "lat": 6.5244 + random.gauss(0, 0.001),
            "lon": 3.3792 + random.gauss(0, 0.001),
            "signal_strength": round(strength, 1),
        })
    return data


# ── Main ingestor ─────────────────────────────────────────────

PARSERS = {
    "ais": parse_ais,
    "adsb": parse_adsb,
    "gps": parse_gps,
}

SIMULATORS = {
    "ais": simulate_ais_fade,
    "adsb": simulate_adsb_fade,
    "gps": simulate_gps_jamming,
}


def ingest(source_type: str, data: List[Dict]) -> Tuple[List[float], List[float]]:
    parser = PARSERS.get(source_type.lower())
    if not parser:
        raise ValueError(f"Unknown source type: {source_type}. Use: ais, adsb, gps")
    return parser(data)


def main():
    parser = argparse.ArgumentParser(description="ThreatFade Satellite Signal Ingestor")
    parser.add_argument("--type", choices=["ais", "adsb", "gps"], required=True)
    parser.add_argument("--file", help="JSON file with telemetry data")
    parser.add_argument("--simulate", action="store_true", help="Use simulated data")
    parser.add_argument("--export", choices=["json", "cef", "none"], default="none")
    args = parser.parse_args()

    print(f"\n{'=' * 56}")
    print(f"  ThreatFade Satellite Signal Fusion")
    print(f"  Source type: {args.type.upper()}")
    print(f"{'=' * 56}\n")

    if args.simulate:
        print(f"[*] Generating simulated {args.type.upper()} fade scenario ...")
        data = SIMULATORS[args.type]()
    elif args.file:
        with open(args.file) as f:
            data = json.load(f)
        print(f"[+] Loaded {len(data)} telemetry records from {args.file}")
    else:
        print("[!] Provide --file or --simulate")
        return

    timestamps, values = ingest(args.type, data)
    print(f"[+] Extracted {len(values)} signal points")

    from core.fade_engine import detect_fade
    from mitre.rule_parser import match_mitre_ttp

    result = detect_fade(timestamps, values)
    mitre = match_mitre_ttp(result) if result["detected"] else "None"

    print(f"\n{'_' * 56}")
    print(f"  Satellite Fade Detection Report")
    print(f"{'_' * 56}")
    print(f"  Source       : {args.type.upper()}")
    print(f"  Data points  : {len(values)}")
    print(f"  Fade detected: {'YES' if result['detected'] else 'NO'}")
    if result["detected"]:
        print(f"  Confidence   : {result['confidence'].upper()}")
        print(f"  Score        : {result['score']:.4f}")
        print(f"  Z-score      : {result['z_outlier']:.2f}")
        print(f"  MITRE TTP    : {mitre}")
    print(f"{'_' * 56}\n")

    if args.export != "none" and result["detected"]:
        from core.siem_exporter import SIEMExporter
        exporter = SIEMExporter()
        path = exporter.export([result], format_type=args.export)
        print(f"[+] Exported: {path}")


if __name__ == "__main__":
    main()
