"""API security controls for ThreatFade."""
import os
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import HTTPException, UploadFile

MAX_PCAP_BYTES = int(os.getenv("THREATFADE_MAX_PCAP_BYTES", str(100 * 1024 * 1024)))
API_KEY = os.getenv("THREATFADE_API_KEY")
ENVIRONMENT = os.getenv("THREATFADE_ENV", "development").lower()
RATE_LIMIT = int(os.getenv("THREATFADE_RATE_LIMIT", "120"))
RATE_WINDOW_SECONDS = int(os.getenv("THREATFADE_RATE_WINDOW_SECONDS", "60"))
_REQUESTS = defaultdict(deque)


def require_api_key(x_api_key: Optional[str]) -> None:
    if ENVIRONMENT == "production" and not API_KEY:
        raise HTTPException(status_code=503, detail="Production API authentication is not configured")
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def enforce_rate_limit(client_id: str) -> None:
    now = time.monotonic()
    bucket = _REQUESTS[client_id]
    while bucket and now - bucket[0] > RATE_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bucket.append(now)


def validate_pcap_upload(file: UploadFile) -> None:
    name = (file.filename or "").lower()
    if not name.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="File must be .pcap or .pcapng")


async def read_limited_upload(file: UploadFile) -> bytes:
    data = await file.read(MAX_PCAP_BYTES + 1)
    if len(data) > MAX_PCAP_BYTES:
        raise HTTPException(status_code=413, detail=f"PCAP exceeds {MAX_PCAP_BYTES} byte limit")
    return data
