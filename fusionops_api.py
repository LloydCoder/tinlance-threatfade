#!/usr/bin/env python3
"""
ThreatFade API wrapper — Tinlance Limited
Exposes the C2 detection engine as a REST service for FusionOps to call.

Run:
    uvicorn fusionops_api:app --host 0.0.0.0 --port 8000 --reload
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import tempfile, os, uuid

from core.fade_engine import detect_fade
from agents.signal_generator import generate_signals
from mitre.rule_parser import match_mitre_ttp
from volatility.memory_sim import simulate_volatility_dump
from pcap_to_threatfade import parse_pcap

app = FastAPI(
    title="ThreatFade API - Tinlance Limited",
    description="C2 evasion detection as a REST service. Validated: Merlin QUIC z-score 14.76.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SignalPayload(BaseModel):
    timestamps: List[float]
    values: List[float]
    source_label: Optional[str] = None

class ScenarioRequest(BaseModel):
    scenario: str = "mixed"

class DetectionResult(BaseModel):
    event_id: str
    timestamp: str
    source: str
    detected: bool
    score: float
    entropy: float
    drop_ratio: float
    z_outlier: float
    fade_start: Optional[int] = None
    mitre_ttp: Optional[str] = None
    volatility_artifacts: Optional[str] = None
    severity: str

def _severity(score):
    if score >= 0.85: return "CRITICAL"
    if score >= 0.65: return "HIGH"
    if score >= 0.40: return "MEDIUM"
    return "LOW"

def _build_result(raw, source):
    mitre = match_mitre_ttp(raw) if raw["detected"] else None
    vol = simulate_volatility_dump(raw) if raw["detected"] else None
    return DetectionResult(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        source=source,
        detected=bool(raw["detected"]),
        score=round(float(raw.get("score", 0)), 4),
        entropy=round(float(raw.get("entropy", 0)), 4),
        drop_ratio=round(float(raw.get("drop_ratio", 0)), 4),
        z_outlier=round(float(raw.get("z_outlier", 0)), 4),
        fade_start=raw.get("fade_start"),
        mitre_ttp=mitre,
        volatility_artifacts=str(vol) if vol else None,
        severity=_severity(float(raw.get("score", 0))),
    )

@app.get("/health", tags=["System"])
def health():
    return {
        "status": "ok",
        "service": "ThreatFade API",
        "version": "0.2.0",
        "engine": "entropy+zscore+rules",
        "validated_on": "Merlin QUIC C2 z-score 14.76"
    }

@app.get("/events", tags=["Monitoring"])
def get_events():
    return {"events": [], "total": 0}

@app.post("/detect/json", response_model=DetectionResult, tags=["Detection"])
def detect_from_json(payload: SignalPayload):
    if len(payload.timestamps) != len(payload.values):
        raise HTTPException(400, "timestamps and values must be the same length")
    if len(payload.values) < 10:
        raise HTTPException(400, "Need at least 10 data points")
    ts = [datetime.fromtimestamp(t) for t in payload.timestamps]
    try:
        raw = detect_fade(ts, payload.values)
    except Exception as e:
        raise HTTPException(500, f"Detection engine error: {str(e)}")
    return _build_result(raw, source=payload.source_label or "json_upload")

@app.post("/detect/scenario", response_model=DetectionResult, tags=["Detection"])
def detect_scenario(request: ScenarioRequest):
    valid = ["c2_quieting", "lotl_gradual", "gnss_jam", "normal_with_fade", "mixed"]
    if request.scenario not in valid:
        raise HTTPException(400, f"scenario must be one of: {valid}")
    try:
        timestamps, values = generate_signals(request.scenario)
        raw = detect_fade(timestamps, values)
    except Exception as e:
        raise HTTPException(500, f"Scenario error: {str(e)}")
    return _build_result(raw, source=f"scenario:{request.scenario}")

@app.post("/detect/pcap", response_model=DetectionResult, tags=["Detection"])
async def detect_from_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(400, "File must be .pcap or .pcapng")
    suffix = ".pcapng" if file.filename.endswith(".pcapng") else ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name
    try:
        try:
            timestamps, values = parse_pcap(tmp_path)
        except ValueError as ve:
            raise HTTPException(422, str(ve))
        except Exception as e:
            raise HTTPException(500, f"PCAP parse error: {str(e)}")
        raw = detect_fade(timestamps, values)
        return _build_result(raw, source=f"pcap:{file.filename}")
    finally:
        os.unlink(tmp_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("fusionops_api:app", host="0.0.0.0", port=8000, reload=True)
