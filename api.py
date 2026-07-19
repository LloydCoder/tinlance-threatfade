#!/usr/bin/env python3
"""
ThreatFade REST API v0.3.0
FastAPI wrapper around the fade detection engine.
Runs locally or on any server. Completely offline.
"""

import os
import math
import tempfile
from datetime import datetime
from collections import defaultdict
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.fade_engine import detect_fade, detect_fade_with_ml
from core.siem_exporter import SIEMExporter
from mitre.rule_parser import match_mitre_ttp
from agents.signal_generator import generate_signals

import yaml
with open("config.yaml", "r") as f:
    CONFIG = yaml.safe_load(f)

app = FastAPI(
    title="ThreatFade API",
    description="Evasion Interception Platform — REST API for fade detection",
    version=CONFIG["branding"]["version"],
)

@app.get("/")
def dashboard():
    return FileResponse("dashboard/index.html")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ─────────────────────────────────

class DetectRequest(BaseModel):
    values: List[float]
    timestamps: Optional[List[float]] = None
    use_ml: bool = False
    export_format: Optional[str] = None


class ScenarioRequest(BaseModel):
    scenario: str = "mixed"
    use_ml: bool = False
    export_format: Optional[str] = None


class DetectionResponse(BaseModel):
    timestamp: str
    detected: bool
    confidence: str
    score: float
    entropy: float
    drop_ratio: float
    z_outlier: float
    fade_start: int
    rules_matched: int
    mitre_ttp: str
    ml_score: Optional[float] = None
    ml_anomaly: Optional[bool] = None
    combined_confidence: Optional[str] = None
    export_path: Optional[str] = None


# ── Helper ────────────────────────────────────────────────────

def _build_response(result, mitre_ttp, source_name, export_format):
    export_path = None
    if export_format and export_format != "none":
        try:
            exporter = SIEMExporter()
            export_path = exporter.export([result], format_type=export_format)
        except Exception as e:
            export_path = f"Export failed: {e}"

    return DetectionResponse(
        timestamp=datetime.now().isoformat(),
        detected=result.get("detected", False),
        confidence=result.get("confidence", "info"),
        score=round(result.get("score", 0.0), 4),
        entropy=round(result.get("entropy", 0.0), 4),
        drop_ratio=round(result.get("drop_ratio", 0.0), 4),
        z_outlier=round(result.get("z_outlier", 0.0), 2),
        fade_start=result.get("fade_start", -1),
        rules_matched=result.get("rules_matched", 0),
        mitre_ttp=mitre_ttp,
        ml_score=round(result.get("ml_score", 0.0), 4),
        ml_anomaly=result.get("ml_anomaly", False),
        combined_confidence=result.get("combined_confidence") or result.get("confidence", "info"),
        export_path=export_path,
    )


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            ent -= p * math.log2(p)
    return ent



def _pcap_to_signals(pcap_path: str, interval_sec: int = 5):
    """
    Hybrid signal extraction from PCAP for fade detection.
    
    Uses BOTH:
    1. Raw payload entropy (when available — unencrypted traffic)
    2. Packet metadata (timing, count, size) — always available, critical for encrypted TLS/HTTPS/QUIC
    
    This hybrid approach maximizes detection accuracy:
    - Unencrypted C2: High entropy signal from Raw payloads
    - Encrypted C2 (TLS/HTTPS/QUIC): Metadata signal from packet timing/count/size
    - Mixed traffic: Combined signal captures both patterns
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, Raw
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="scapy not installed. Run: pip install scapy"
        )
    
    packets = rdpcap(pcap_path)
    
    # Collect ALL packets with IP layer
    packet_events = []
    for pkt in packets:
        if IP in pkt:
            ts = float(pkt.time)
            size = len(pkt)
            
            # Payload size if available
            payload_size = 0
            if TCP in pkt and hasattr(pkt[TCP], 'payload'):
                payload_size = len(bytes(pkt[TCP].payload))
            elif UDP in pkt and hasattr(pkt[UDP], 'payload'):
                payload_size = len(bytes(pkt[UDP].payload))
            
            # Raw payload entropy if available
            raw_entropy = None
            if Raw in pkt:
                raw_data = bytes(pkt[Raw].load)
                if len(raw_data) > 0:
                    raw_entropy = _byte_entropy(raw_data)
            
            packet_events.append({
                'time': ts,
                'size': size,
                'payload_size': payload_size,
                'raw_entropy': raw_entropy,
                'src': pkt[IP].src,
                'dst': pkt[IP].dst,
            })
    
    if not packet_events:
        return list(range(20)), [0.5] * 20
    
    # Sort by time
    packet_events.sort(key=lambda x: x['time'])
    
    start_t = int(packet_events[0]['time'])
    end_t = int(packet_events[-1]['time'])
    duration = end_t - start_t
    
    # Adaptive interval
    if duration < 30:
        interval_sec = 1
    elif duration > 600:
        interval_sec = 10
    else:
        interval_sec = 5
    
    # Build time-series per bucket
    timestamps = []
    values = []
    current = start_t
    
    while current <= end_t:
        bucket = [p for p in packet_events if current <= p['time'] < current + interval_sec]
        
        if bucket:
            pkt_count = len(bucket)
            total_bytes = sum(p['size'] for p in bucket)
            total_payload = sum(p['payload_size'] for p in bucket)
            
            # Metadata signals
            count_score = min(1.0, pkt_count / 100.0)
            byte_score = min(1.0, total_bytes / 50000.0)
            payload_ratio = total_payload / total_bytes if total_bytes > 0 else 0
            
            # Entropy signal (only from packets with Raw payload)
            entropy_values = [p['raw_entropy'] for p in bucket if p['raw_entropy'] is not None]
            if entropy_values:
                mean_entropy = sum(entropy_values) / len(entropy_values)
                # Shannon entropy max is 8.0 for random bytes, normalize to 0-1
                entropy_score = min(1.0, mean_entropy / 8.0)
                
                # HYBRID: When entropy is available, weight it heavily
                packets_with_raw = len(entropy_values)
                raw_ratio = packets_with_raw / pkt_count
                
                if raw_ratio >= 0.5:
                    # Mostly unencrypted — entropy is reliable
                    signal = (0.5 * entropy_score) + (0.2 * count_score) + (0.2 * byte_score) + (0.1 * payload_ratio)
                else:
                    # Mostly encrypted — metadata is primary
                    signal = (0.1 * entropy_score) + (0.4 * count_score) + (0.3 * byte_score) + (0.2 * payload_ratio)
            else:
                # No Raw payloads at all (fully encrypted like TLS/HTTPS/QUIC)
                signal = (0.5 * count_score) + (0.3 * byte_score) + (0.2 * payload_ratio)
        else:
            signal = 0.0  # Silence = fade window
        
        timestamps.append(current - start_t)
        values.append(signal)
        current += interval_sec
    
    # Ensure minimum data points
    if len(values) < 12:
        while len(values) < 12:
            values.append(0.0)
            timestamps.append(timestamps[-1] + interval_sec if timestamps else len(timestamps))
    
    # Normalize to 0-1 using min-max (preserves relative drops)
    max_val = max(values) if max(values) > 0 else 1.0
    min_val = min(values)
    if max_val > min_val:
        values = [(v - min_val) / (max_val - min_val) for v in values]
    
    return timestamps, values

@app.get("/health")
@app.get("/health")
def health():
    return {
        "status": "ok",
        "tool": "ThreatFade",
        "version": CONFIG["branding"]["version"],
        "company": CONFIG["branding"]["company"],
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/version")
def version():
    return {
        "name": CONFIG["branding"]["name"],
        "version": CONFIG["branding"]["version"],
        "company": CONFIG["branding"]["company"],
        "license": "Apache 2.0 (open-core)",
    }


@app.post("/detect", response_model=DetectionResponse)
def detect(req: DetectRequest):
    if not req.values or len(req.values) < 12:
        raise HTTPException(
            status_code=400,
            detail=f"Need at least 12 signal values, got {len(req.values) if req.values else 0}"
        )
    timestamps = req.timestamps or list(range(len(req.values)))

    if req.use_ml:
        try:
            from core.ml_stub import MLDetector
            ml = MLDetector()
            if not ml.trained:
                ml.train_from_generator()
            result = detect_fade_with_ml(timestamps, req.values, ml_detector=ml)
        except Exception:
            result = detect_fade(timestamps, req.values)
    else:
        result = detect_fade(timestamps, req.values)

    mitre_ttp = match_mitre_ttp(result) if result["detected"] else "None"
    return _build_response(result, mitre_ttp, "api_detect", req.export_format)


@app.post("/detect/pcap", response_model=DetectionResponse)
async def detect_pcap(
    file: UploadFile = File(...),
    use_ml: bool = False,
    export_format: Optional[str] = None,
):
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="File must be .pcap or .pcapng"
        )

    with tempfile.NamedTemporaryFile(
        delete=False, suffix=".pcap"
    ) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        timestamps, values = _pcap_to_signals(tmp_path)
    finally:
        os.unlink(tmp_path)

    if use_ml:
        try:
            from core.ml_stub import MLDetector
            ml = MLDetector()
            if not ml.trained:
                ml.train_from_generator()
            result = detect_fade_with_ml(timestamps, values, ml_detector=ml)
        except Exception:
            result = detect_fade(timestamps, values)
    else:
        result = detect_fade(timestamps, values)

    mitre_ttp = match_mitre_ttp(result) if result["detected"] else "None"
    source = file.filename.replace(" ", "_")
    return _build_response(result, mitre_ttp, source, export_format)


@app.post("/detect/scenario", response_model=DetectionResponse)
def detect_scenario(req: ScenarioRequest):
    valid = ["c2_quieting", "lotl_gradual", "gnss_jam", "normal_with_fade", "mixed"]
    if req.scenario not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario. Choose from: {valid}"
        )

    timestamps, values = generate_signals(req.scenario)

    if req.use_ml:
        try:
            from core.ml_stub import MLDetector
            ml = MLDetector()
            if not ml.trained:
                ml.train_from_generator()
            result = detect_fade_with_ml(timestamps, values, ml_detector=ml)
        except Exception:
            result = detect_fade(timestamps, values)
    else:
        result = detect_fade(timestamps, values)

    mitre_ttp = match_mitre_ttp(result) if result["detected"] else "None"
    return _build_response(result, mitre_ttp, req.scenario, req.export_format)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8080, reload=False)
