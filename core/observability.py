"""Optional OpenTelemetry instrumentation with a safe no-op fallback."""
from contextlib import contextmanager
from typing import Iterator, Optional

try:
    from opentelemetry import trace
    _TRACER = trace.get_tracer("threatfade")
except Exception:  # pragma: no cover - optional dependency
    _TRACER = None


@contextmanager
def span(name: str) -> Iterator[Optional[object]]:
    if _TRACER is None:
        yield None
        return
    with _TRACER.start_as_current_span(name) as current:
        yield current
