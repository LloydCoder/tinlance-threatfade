"""Low-cardinality observability primitives for the ThreatFade API."""
from __future__ import annotations

from contextlib import contextmanager
from time import perf_counter
from typing import Iterator, Optional

try:
    from opentelemetry import trace
    _TRACER = trace.get_tracer("threatfade")
except Exception:  # pragma: no cover - optional SDK/API mismatch
    _TRACER = None

try:
    from prometheus_client import Counter, Gauge, Histogram, Info, make_asgi_app
    HTTP_REQUESTS = Counter("threatfade_http_requests_total", "HTTP requests", ["method", "route", "status"])
    HTTP_LATENCY = Histogram("threatfade_http_request_duration_seconds", "HTTP request duration", ["method", "route"])
    IN_FLIGHT = Gauge("threatfade_http_requests_in_flight", "HTTP requests currently executing")
    DETECTIONS = Counter("threatfade_detections_total", "Detection attempts", ["outcome"])
    RESILIENCE_REJECTIONS = Counter("threatfade_resilience_rejections_total", "Rejected work", ["reason"])
    BUILD_INFO = Info("threatfade_build", "ThreatFade build metadata")
    PROMETHEUS_AVAILABLE = True
except Exception:  # pragma: no cover - metrics dependency optional for library users
    PROMETHEUS_AVAILABLE = False
    HTTP_REQUESTS = HTTP_LATENCY = IN_FLIGHT = DETECTIONS = RESILIENCE_REJECTIONS = BUILD_INFO = None
    make_asgi_app = None


def initialize_metrics(*, version: str, environment: str) -> None:
    if PROMETHEUS_AVAILABLE:
        BUILD_INFO.info({"version": str(version), "environment": str(environment)})


def record_detection(outcome: str) -> None:
    if PROMETHEUS_AVAILABLE:
        DETECTIONS.labels(outcome=outcome).inc()


def record_rejection(reason: str) -> None:
    if PROMETHEUS_AVAILABLE:
        RESILIENCE_REJECTIONS.labels(reason=reason).inc()


@contextmanager
def span(name: str) -> Iterator[Optional[object]]:
    if _TRACER is None:
        yield None
        return
    with _TRACER.start_as_current_span(name) as current:
        yield current


@contextmanager
def request_metrics(method: str, route: str):
    start = perf_counter()
    if PROMETHEUS_AVAILABLE:
        IN_FLIGHT.inc()
    status = "500"
    try:
        yield lambda value: _set_status(value)
    except Exception:
        raise
    finally:
        if PROMETHEUS_AVAILABLE:
            HTTP_LATENCY.labels(method=method, route=route).observe(perf_counter() - start)
            IN_FLIGHT.dec()


def _set_status(value: int) -> None:
    # Kept as a tiny hook for callers; status is recorded by the ASGI middleware.
    return None


def metrics_app():
    if not PROMETHEUS_AVAILABLE or make_asgi_app is None:
        return None
    return make_asgi_app()


def observe_http(method: str, route: str, status: int, duration: float) -> None:
    if PROMETHEUS_AVAILABLE:
        HTTP_REQUESTS.labels(method=method, route=route, status=str(status)).inc()
        HTTP_LATENCY.labels(method=method, route=route).observe(duration)
