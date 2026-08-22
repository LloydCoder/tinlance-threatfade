import asyncio

import pytest

from core.reliability import (
    AsyncBulkhead, Bulkhead, BulkheadRejectedError, CircuitBreaker, CircuitOpenError,
    RetryExhaustedError, RetryPolicy, retry_call,
)


def test_retry_succeeds_after_transient_failures():
    calls = {"n": 0}
    def operation():
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError("temporary")
        return "ok"
    assert retry_call(operation, policy=RetryPolicy(attempts=3, base_delay=0, jitter=0)) == "ok"
    assert calls["n"] == 3


def test_retry_does_not_retry_non_transient_errors():
    calls = {"n": 0}
    def operation():
        calls["n"] += 1
        raise ValueError("bad input")
    with pytest.raises(ValueError):
        retry_call(operation, policy=RetryPolicy(attempts=3, base_delay=0, jitter=0))
    assert calls["n"] == 1


def test_retry_exhaustion_is_explicit():
    with pytest.raises(RetryExhaustedError):
        retry_call(lambda: (_ for _ in ()).throw(ConnectionError("down")), policy=RetryPolicy(attempts=2, base_delay=0, jitter=0))


def test_circuit_opens_and_recovers():
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
    for _ in range(2):
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("down")))
    assert breaker.state == "open"
    with pytest.raises(CircuitOpenError):
        breaker.call(lambda: "must-not-run")
    import time; time.sleep(0.02)
    assert breaker.state == "half_open"
    assert breaker.call(lambda: "recovered") == "recovered"
    assert breaker.state == "closed"


def test_bulkhead_rejects_without_queueing():
    bulkhead = Bulkhead(1)
    held = threading_event = __import__("threading").Event()
    release = __import__("threading").Event()
    def worker():
        bulkhead.call(lambda: (held.set(), release.wait(1)))
    thread = __import__("threading").Thread(target=worker)
    thread.start(); assert held.wait(1)
    with pytest.raises(BulkheadRejectedError):
        bulkhead.call(lambda: None)
    release.set(); thread.join(1)


def test_async_bulkhead_rejects_second_task():
    async def run():
        bulkhead = AsyncBulkhead(1)
        started = asyncio.Event(); release = asyncio.Event()
        async def first():
            started.set(); await release.wait(); return "first"
        task = asyncio.create_task(bulkhead.call(first)); await started.wait()
        with pytest.raises(BulkheadRejectedError):
            await bulkhead.call(lambda: asyncio.sleep(0, result="second"))
        release.set(); assert await task == "first"
    asyncio.run(run())
