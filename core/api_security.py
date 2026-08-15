"""API security controls for ThreatFade."""
import os
from typing import Optional

from fastapi import Header, HTTPException, UploadFile

MAX_PCAP_BYTES = int(os.getenv("THREATFADE_MAX_PCAP_BYTES", str(100 * 1024 * 1024)))
API_KEY = os.getenv("THREATFADE_API_KEY")


def require_api_key(x_api_key: Optional[str]) -> None:
    """Require a key only when THREATFADE_API_KEY is configured."""
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def validate_pcap_upload(file: UploadFile) -> None:
    name = (file.filename or "").lower()
    if not name.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="File must be .pcap or .pcapng")


async def read_limited_upload(file: UploadFile) -> bytes:
    data = await file.read(MAX_PCAP_BYTES + 1)
    if len(data) > MAX_PCAP_BYTES:
        raise HTTPException(status_code=413, detail=f"PCAP exceeds {MAX_PCAP_BYTES} byte limit")
    return data
