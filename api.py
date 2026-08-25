#!/usr/bin/env python3
"""ThreatFade REST API with enterprise identity, tenancy, authorization and observability."""
import math
import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

import yaml
from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from agents.signal_generator import generate_signals
from core.api_security import enforce_rate_limit, read_limited_upload, validate_pcap_upload
from core.enterprise import AUDIT, authenticate, authorize, require_tenant, slo_targets
from core.explainability import build_evidence
from core.fade_engine import detect_fade, detect_fade_with_ml
from core.identity_routes import router as identity_router
from core.analyst_routes import router as analyst_router
from core.interoperability import to_sigma, to_stix_bundle
from core.observability import span
from core.siem_exporter import SIEMExporter
from core.storage import list_detections, save_detection
from mitre.rule_parser import match_mitre_ttp

with open("config.yaml", "r", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)

ENVIRONMENT = os.getenv("THREATFADE_ENV", "development").lower()
MAX_BODY_BYTES = int(os.getenv("THREATFADE_MAX_BODY_BYTES", str(2 * 1024 * 1024)))
allowed_origins = [x.strip() for x in os.getenv("THREATFADE_ALLOWED_ORIGINS", "http://localhost:8080").split(",") if x.strip()]
if ENVIRONMENT == "production" and "*" in allowed_origins:
    raise RuntimeError("Wildcard CORS is forbidden in production")

app = FastAPI(title="ThreatFade API", description="Evasion Interception Platform", version=CONFIG["branding"]["version"], docs_url="/docs", redoc_url="/redoc")
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-API-Key", "Authorization", "X-Request-ID", "X-Tenant-ID", "X-ThreatFade-Session"])


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        if request.headers.get("Content-Length"):
            try:
                if int(request.headers["Content-Length"]) > MAX_BODY_BYTES:
                    return await _json_error(413, "Request body exceeds configured limit", request_id)
            except ValueError:
                return await _json_error(400, "Invalid Content-Length", request_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store" if request.url.path.startswith(("/detect", "/detections", "/enterprise")) else "no-cache"
        if ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        return response


async def _json_error(status: int, detail: str, request_id: str):
    from fastapi.responses import JSONResponse
    response = JSONResponse(status_code=status, content={"detail": detail, "request_id": request_id})
    response.headers["X-Request-ID"] = request_id
    return response


app.add_middleware(SecurityHeadersMiddleware)
app.include_router(identity_router)
app.include_router(analyst_router)


class DetectRequest(BaseModel):
    values: List[float] = Field(..., max_length=100000)
    timestamps: Optional[List[float]] = None
    use_ml: bool = False
    export_format: Optional[str] = None
    tenant_id: Optional[str] = Field(default=None, max_length=255)


class ScenarioRequest(BaseModel):
    scenario: str = "mixed"
    use_ml: bool = False
    export_format: Optional[str] = None
    tenant_id: Optional[str] = Field(default=None, max_length=255)


class DetectionResponse(BaseModel):
    timestamp: str
    detection_id: Optional[int] = None
    tenant_id: str
    detected: bool
    confidence: str
    score: float
    entropy: float
    drop_ratio: float
    z_outlier: float
    fade_start: int
    rules_matched: int
    mitre_ttp: str
    evidence: Dict[str, object]
    ml_score: Optional[float] = None
    ml_anomaly: Optional[bool] = None
    combined_confidence: Optional[str] = None
    export_path: Optional[str] = None


def _guard(request: Request, x_api_key: Optional[str], permission: str):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    principal = authenticate(request, x_api_key)
    tenant_id = require_tenant(principal, request.headers.get("X-Tenant-ID"))
    authorize(principal, permission)
    AUDIT.record("authorization", principal, request, {"permission": permission, "tenant_id": tenant_id})
    return principal, tenant_id


def _run_detection(timestamps, values, use_ml: bool):
    with span("threatfade.detect"):
        if use_ml:
            try:
                from core.ml_stub import MLDetector
                ml = MLDetector()
                if not ml.trained:
                    ml.train_from_generator()
                return detect_fade_with_ml(timestamps, values, ml_detector=ml)
            except Exception:
                pass
        return detect_fade(timestamps, values)


def _build_response(result, mitre_ttp, source_name, export_format, principal, tenant_id):
    result = dict(result)
    result["evidence"] = build_evidence(result)
    export_path = None
    if export_format and export_format.lower() not in {"none", ""}:
        authorize(principal, "export:write")
        fmt = export_format.lower()
        if fmt in {"sigma", "stix", "stix2.1"}:
            payload = to_sigma(result, title=f"ThreatFade: {source_name}") if fmt == "sigma" else to_stix_bundle(result, source_name)
            output = os.path.join("reports", "interoperability")
            os.makedirs(output, exist_ok=True)
            ext = "yml" if fmt == "sigma" else "json"
            path = os.path.join(output, f"{tenant_id}_{source_name}.{ext}")
            import json
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            export_path = path
    detection_id = save_detection(tenant_id, principal.subject, source_name, result, mitre_ttp)
    AUDIT.record("detection.created", principal, metadata={"detection_id": detection_id, "source": source_name, "tenant_id": tenant_id})
    return DetectionResponse(timestamp=datetime.now(timezone.utc).isoformat(), detection_id=detection_id, tenant_id=tenant_id, detected=bool(result.get("detected", False)), confidence=result.get("confidence", "info"), score=round(float(result.get("score", 0.0)), 4), entropy=round(float(result.get("entropy", 0.0)), 4), drop_ratio=round(float(result.get("drop_ratio", 0.0)), 4), z_outlier=round(float(result.get("z_outlier", 0.0)), 2), fade_start=int(result.get("fade_start", -1)), rules_matched=int(result.get("rules_matched", 0)), mitre_ttp=mitre_ttp, evidence=result["evidence"], ml_score=round(float(result.get("ml_score", 0.0)), 4), ml_anomaly=bool(result.get("ml_anomaly", False)), combined_confidence=result.get("combined_confidence") or result.get("confidence", "info"), export_path=export_path)


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    for count in freq:
        if count:
            p = count / len(data)
            ent -= p * math.log2(p)
    return ent


def _pcap_to_signals(pcap_path: str, interval_sec: int = 5):
    try:
        from scapy.all import IP, Raw, TCP, UDP, rdpcap
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="scapy is required for PCAP ingestion") from exc
    try:
        packets = rdpcap(pcap_path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid or unreadable PCAP") from exc
    events = []
    for pkt in packets:
        if IP not in pkt:
            continue
        payload_size = len(bytes(pkt[TCP].payload)) if TCP in pkt else len(bytes(pkt[UDP].payload)) if UDP in pkt else 0
        raw_entropy = _byte_entropy(bytes(pkt[Raw].load)) if Raw in pkt and bytes(pkt[Raw].load) else None
        events.append({"time": float(pkt.time), "size": len(pkt), "payload_size": payload_size, "raw_entropy": raw_entropy})
    if not events:
        return list(range(20)), [0.5] * 20
    events.sort(key=lambda item: item["time"])
    start, end = int(events[0]["time"]), int(events[-1]["time"])
    duration = end - start
    interval_sec = 1 if duration < 30 else 10 if duration > 600 else interval_sec
    timestamps, values, current = [], [], start
    while current <= end:
        bucket = [p for p in events if current <= p["time"] < current + interval_sec]
        if not bucket:
            signal = 0.0
        else:
            count_score = min(1.0, len(bucket) / 100.0)
            total_bytes = sum(p["size"] for p in bucket)
            byte_score = min(1.0, total_bytes / 50000.0)
            payload_ratio = sum(p["payload_size"] for p in bucket) / total_bytes if total_bytes else 0.0
            entropies = [p["raw_entropy"] for p in bucket if p["raw_entropy"] is not None]
            entropy_score = (sum(entropies) / len(entropies)) / 8.0 if entropies else 0.0
            raw_ratio = len(entropies) / len(bucket)
            signal = (0.5 * entropy_score + 0.2 * count_score + 0.2 * byte_score + 0.1 * payload_ratio) if raw_ratio >= 0.5 else (0.1 * entropy_score + 0.4 * count_score + 0.3 * byte_score + 0.2 * payload_ratio)
        timestamps.append(current - start)
        values.append(float(signal))
        current += interval_sec
    while len(values) < 12:
        values.append(0.0)
        timestamps.append((timestamps[-1] + interval_sec) if timestamps else len(timestamps))
    lo, hi = min(values), max(values)
    if hi > lo:
        values = [(v - lo) / (hi - lo) for v in values]
    return timestamps, values


@app.get("/")
def dashboard():
    return FileResponse("dashboard/index.html")


@app.get("/health")
def health():
    return {"status": "ok", "tool": "ThreatFade", "version": CONFIG["branding"]["version"], "company": CONFIG["branding"]["company"], "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/ready")
def readiness():
    checks = {"config": bool(CONFIG), "dashboard": os.path.exists("dashboard/index.html"), "storage": True}
    ready = all(checks.values())
    if not ready:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "checks": checks})
    return {"status": "ready", "checks": checks, "version": CONFIG["branding"]["version"], "slo": slo_targets()}


@app.get("/version")
def version():
    return {"name": CONFIG["branding"]["name"], "version": CONFIG["branding"]["version"], "company": CONFIG["branding"]["company"], "license": "Apache 2.0 (open-core)"}


@app.get("/detections")
def detections(request: Request, x_api_key: Optional[str] = Header(default=None), limit: int = 100):
    principal, tenant_id = _guard(request, x_api_key, "detection:read")
    limit = max(1, min(limit, 500))
    records = list_detections(tenant_id, limit)
    return {"tenant_id": tenant_id, "items": [{"id": r.id, "source": r.source, "detected": bool(r.detected), "confidence": r.confidence, "score": r.score, "mitre_ttp": r.mitre_ttp, "created_at": r.created_at.isoformat()} for r in records]}


@app.get("/enterprise/auth-config")
def auth_config():
    return {"oidc_required_in_production": True, "issuer_configured": bool(os.getenv("THREATFADE_OIDC_ISSUER")), "rbac_roles": ["owner", "admin", "analyst", "viewer"]}


@app.post("/detect", response_model=DetectionResponse)
def detect(req: DetectRequest, request: Request, x_api_key: Optional[str] = Header(default=None)):
    principal, tenant_id = _guard(request, x_api_key, "detection:run")
    tenant_id = require_tenant(principal, req.tenant_id)
    if len(req.values) < 12:
        raise HTTPException(status_code=400, detail=f"Need at least 12 signal values, got {len(req.values)}")
    if any(not math.isfinite(v) for v in req.values):
        raise HTTPException(status_code=400, detail="Signal values must be finite numbers")
    if req.timestamps is not None:
        if len(req.timestamps) != len(req.values):
            raise HTTPException(status_code=400, detail="timestamps length must match values length")
        if any(not math.isfinite(v) for v in req.timestamps):
            raise HTTPException(status_code=400, detail="timestamps must be finite numbers")
    timestamps = req.timestamps or list(range(len(req.values)))
    result = _run_detection(timestamps, req.values, req.use_ml)
    return _build_response(result, match_mitre_ttp(result) if result["detected"] else "None", "api_detect", req.export_format, principal, tenant_id)


@app.post("/detect/pcap", response_model=DetectionResponse)
async def detect_pcap(request: Request, file: UploadFile = File(...), use_ml: bool = False, export_format: Optional[str] = None, x_api_key: Optional[str] = Header(default=None)):
    principal, tenant_id = _guard(request, x_api_key, "detection:run")
    validate_pcap_upload(file)
    content = await read_limited_upload(file)
    suffix = ".pcapng" if (file.filename or "").lower().endswith(".pcapng") else ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    try:
        timestamps, values = _pcap_to_signals(tmp_path)
        result = _run_detection(timestamps, values, use_ml)
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
    return _build_response(result, match_mitre_ttp(result) if result["detected"] else "None", "upload", export_format, principal, tenant_id)


@app.post("/detect/scenario", response_model=DetectionResponse)
def detect_scenario(req: ScenarioRequest, request: Request, x_api_key: Optional[str] = Header(default=None)):
    principal, tenant_id = _guard(request, x_api_key, "detection:run")
    tenant_id = require_tenant(principal, req.tenant_id)
    valid = ["c2_quieting", "lotl_gradual", "gnss_jam", "normal_with_fade", "mixed"]
    if req.scenario not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid scenario. Choose from: {valid}")
    timestamps, values = generate_signals(req.scenario)
    result = _run_detection(timestamps, values, req.use_ml)
    return _build_response(result, match_mitre_ttp(result) if result["detected"] else "None", req.scenario, req.export_format, principal, tenant_id)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8080, reload=False)
