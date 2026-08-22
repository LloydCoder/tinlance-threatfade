"""Health and readiness checks with explicit dependency semantics."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from sqlalchemy import text
from sqlalchemy.orm import Session

from .storage import ENGINE


def check_storage() -> dict[str, object]:
    started = datetime.now(timezone.utc)
    try:
        with Session(ENGINE) as session:
            session.execute(text("SELECT 1"))
        return {"status": "ok", "latency_ms": round((datetime.now(timezone.utc) - started).total_seconds() * 1000, 2), "dialect": ENGINE.dialect.name}
    except Exception as exc:
        return {"status": "failed", "error": type(exc).__name__, "dialect": ENGINE.dialect.name}


def readiness_checks() -> dict[str, dict[str, object]]:
    return {
        "config": {"status": "ok"},
        "dashboard": {"status": "ok" if os.path.exists("dashboard/index.html") else "failed"},
        "storage": check_storage(),
    }


def readiness_state(*, draining: bool) -> tuple[bool, dict[str, dict[str, object]]]:
    checks = readiness_checks()
    if draining:
        checks["lifecycle"] = {"status": "draining"}
    else:
        checks["lifecycle"] = {"status": "running"}
    ready = not draining and all(item.get("status") == "ok" for key, item in checks.items() if key != "lifecycle")
    return ready, checks
