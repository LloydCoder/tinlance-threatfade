"""Production application entrypoint with reliability and observability controls."""
from __future__ import annotations

from contextlib import asynccontextmanager
from time import perf_counter
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from api import app
from core.enterprise_routes import router as enterprise_router
from core.health import readiness_state
from core.observability import initialize_metrics, observe_http, metrics_app
from core.reliability_routes import router as reliability_router


@asynccontextmanager
async def lifespan(_app):
    _app.state.draining = False
    initialize_metrics(version=str(_app.version), environment=os.getenv("THREATFADE_ENV", "development"))
    yield
    _app.state.draining = True


app.router.lifespan_context = lifespan


class ReliabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        started = perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            observe_http(request.method, request.url.path, 500, perf_counter() - started)
            raise
        route = request.scope.get("route")
        route_name = getattr(route, "path", None) or request.url.path
        observe_http(request.method, route_name, response.status_code, perf_counter() - started)
        response.headers.setdefault("X-Request-Duration-Ms", f"{(perf_counter() - started) * 1000:.2f}")
        return response


app.add_middleware(ReliabilityMiddleware)
app.include_router(enterprise_router)
app.include_router(reliability_router)

_metrics = metrics_app()
if _metrics is not None:
    app.mount("/metrics", _metrics)


@app.get("/health")
def production_health():
    return {"status": "ok", "version": app.version, "environment": os.getenv("THREATFADE_ENV", "development").lower()}


@app.get("/ready")
def production_readiness():
    draining = bool(getattr(app.state, "draining", False))
    ready, checks = readiness_state(draining=draining)
    if not ready:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail={"status": "not_ready", "checks": checks})
    return {"status": "ready", "checks": checks, "version": app.version}
