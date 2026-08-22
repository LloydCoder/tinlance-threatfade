"""Operational endpoints and process lifecycle state for production orchestration."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .health import readiness_state
from .observability import PROMETHEUS_AVAILABLE

router = APIRouter(tags=["operations"])


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


@router.get("/startup")
def startup(app_state=None):
    # The production wrapper replaces this with its lifecycle state when mounted.
    return {"status": "started"}


@router.get("/readyz")
def readyz():
    ready, checks = readiness_state(draining=False)
    if not ready:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "checks": checks})
    return {"status": "ready", "checks": checks}


@router.get("/metrics/status")
def metrics_status():
    return {"prometheus_client": PROMETHEUS_AVAILABLE}
