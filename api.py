#!/usr/bin/env python3
"""
ThreatFade REST API
FastAPI wrapper around the fade detection engine.
Runs locally or on any server. Completely offline.

Usage:
    python api.py
    # or
    uvicorn api:app --host 0.0.0.0 --port 8080

Endpoints:
    GET  /health
    GET  /version
    POST /detect
    POST /detect/pcap
    POST /detect/scenario
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


def _pcap_to_signals(pcap_path: str, interval_sec: int = 60):
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, Raw
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="scapy not installed. Run: pip install scapy"
        )
    packets = rdpcap(pcap_path)
    sessions = defaultdict(list)
    for pkt in packets:
        if IP in pkt and Raw in pkt and (TCP in pkt or UDP in pkt):
            sessions[float(pkt.time)].append(pkt[Raw].load)
    if not sessions:
        return list(range(20)), [0.5] * 20
    all_times = sorted(sessions.keys())
    start_t = int(all_times[0])
    end_t = int(all_times[-1])
    timestamps, entropy_values = [], []
    current = start_t
    while current < end_t:
        payloads = []
        for t in all_times:
            if current <= t < current + interval_sec:
                payloads.extend(sessions[t])
        ent = _byte_entropy(b"".join(payloads)) if payloads else 0.0
        timestamps.append(current - start_t)
        entropy_values.append(ent)
        current += interval_sec
    return timestamps, entropy_values


# ── Endpoints ─────────────────────────────────────────────────

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
            detail=f"Need at least 12 signal values, got {len(req.values)}"
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
