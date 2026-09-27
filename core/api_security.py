"""API security controls for ThreatFade."""
from __future__ import annotations

import hashlib
import os
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import HTTPException, UploadFile
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.storage import ENGINE

MAX_PCAP_BYTES = int(os.getenv("THREATFADE_MAX_PCAP_BYTES", str(100 * 1024 * 1024)))
MAX_PCAP_PACKETS = int(os.getenv("THREATFADE_MAX_PCAP_PACKETS", "1000000"))
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


def _shared_rate_limit(client_id: str) -> bool:
    bucket_key = hashlib.sha256(client_id.encode("utf-8")).hexdigest()
    window_start = int(time.time()) // RATE_WINDOW_SECONDS
    with Session(ENGINE) as session:
        session.execute(
            text(
                """
                INSERT INTO rate_limit_buckets(bucket_key, window_start, request_count)
                VALUES (:bucket_key, :window_start, 1)
                ON CONFLICT (bucket_key) DO UPDATE
                SET
                    window_start = CASE
                        WHEN rate_limit_buckets.window_start = :window_start
                        THEN rate_limit_buckets.window_start
                        ELSE :window_start
                    END,
                    request_count = CASE
                        WHEN rate_limit_buckets.window_start = :window_start
                        THEN rate_limit_buckets.request_count + 1
                        ELSE 1
                    END
                """
            ),
            {"bucket_key": bucket_key, "window_start": window_start},
        )
        count = session.execute(
            text("SELECT request_count FROM rate_limit_buckets WHERE bucket_key = :bucket_key"),
            {"bucket_key": bucket_key},
        ).scalar_one()
        session.commit()
    return int(count) <= RATE_LIMIT


def enforce_rate_limit(client_id: str) -> None:
    if not client_id or len(client_id) > 512:
        raise HTTPException(status_code=400, detail="Invalid client identifier")
    if ENGINE.dialect.name == "postgresql":
        try:
            if not _shared_rate_limit(client_id):
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            return
        except HTTPException:
            raise
        except Exception:
            if ENVIRONMENT == "production":
                raise HTTPException(status_code=503, detail="Rate-limit service unavailable")
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
