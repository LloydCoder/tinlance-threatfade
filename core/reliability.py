"""Small, dependency-free resilience primitives for ThreatFade.

The primitives are intentionally deterministic and synchronous because they are
used around CPU/disk/HTTP integration boundaries. They fail closed: exhausted
retries and open circuits raise rather than silently dropping security work.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
import random
import threading
import time
from typing import Callable, TypeVar

T = TypeVar("T")


class RetryExhaustedError(RuntimeError):
    """Raised when a transient operation remains unavailable after retries."""


class CircuitOpenError(RuntimeError):
    """Raised when a circuit is open and calls are intentionally rejected."""


class BulkheadRejectedError(RuntimeError):
    """Raised when the configured concurrency budget is exhausted."""


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 3
    base_delay: float = 0.05
    max_delay: float = 1.0
    jitter: float = 0.10

    def __post_init__(self) -> None:
        if self.attempts < 1 or self.base_delay < 0 or self.max_delay < self.base_delay or self.jitter < 0:
            raise ValueError("invalid retry policy")


def retry_call(fn: Callable[[], T], *, policy: RetryPolicy = RetryPolicy(), retryable: tuple[type[BaseException], ...] = (TimeoutError, ConnectionError, OSError)) -> T:
    last: BaseException | None = None
    for attempt in range(policy.attempts):
        try:
            return fn()
        except retryable as exc:
            last = exc
            if attempt + 1 == policy.attempts:
                break
            delay = min(policy.max_delay, policy.base_delay * (2 ** attempt))
            if policy.jitter:
                delay += random.uniform(0, policy.jitter * delay)
            time.sleep(delay)
    raise RetryExhaustedError(f"operation failed after {policy.attempts} attempts") from last


def retry(policy: RetryPolicy = RetryPolicy(), retryable: tuple[type[BaseException], ...] = (TimeoutError, ConnectionError, OSError)):
    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @wraps(fn)
        def wrapped(*args, **kwargs):
            return retry_call(lambda: fn(*args, **kwargs), policy=policy, retryable=retryable)
        return wrapped
    return decorator


class CircuitBreaker:
    """Thread-safe closed/open/half-open circuit with bounded recovery probes."""

    def __init__(self, *, failure_threshold: int = 5, recovery_timeout: float = 30.0, half_open_calls: int = 1) -> None:
        if failure_threshold < 1 or recovery_timeout <= 0 or half_open_calls < 1:
            raise ValueError("invalid circuit breaker configuration")
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_calls = half_open_calls
        self._lock = threading.Lock()
        self._state = "closed"
        self._failures = 0
        self._opened_at = 0.0
        self._probes = 0

    @property
    def state(self) -> str:
        with self._lock:
            self._refresh_state_locked()
            return self._state

    @property
    def failures(self) -> int:
        with self._lock:
            return self._failures

    def _refresh_state_locked(self) -> None:
        if self._state == "open" and time.monotonic() - self._opened_at >= self.recovery_timeout:
            self._state = "half_open"
            self._probes = 0

    def allow(self) -> bool:
        with self._lock:
            self._refresh_state_locked()
            if self._state == "closed":
                return True
            if self._state == "half_open" and self._probes < self.half_open_calls:
                self._probes += 1
                return True
            return False

    def success(self) -> None:
        with self._lock:
            self._state = "closed"
            self._failures = 0
            self._probes = 0

    def failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._state == "half_open" or self._failures >= self.failure_threshold:
                self._state = "open"
                self._opened_at = time.monotonic()
                self._probes = 0

    def call(self, fn: Callable[[], T]) -> T:
        if not self.allow():
            raise CircuitOpenError("circuit is open")
        try:
            result = fn()
        except Exception:
            self.failure()
            raise
        self.success()
        return result


class Bulkhead:
    """Concurrency limiter that rejects rather than queues unbounded work."""

    def __init__(self, max_concurrency: int) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        self.max_concurrency = max_concurrency
        self._semaphore = threading.BoundedSemaphore(max_concurrency)

    def call(self, fn: Callable[[], T]) -> T:
        if not self._semaphore.acquire(blocking=False):
            raise BulkheadRejectedError("concurrency budget exhausted")
        try:
            return fn()
        finally:
            self._semaphore.release()
