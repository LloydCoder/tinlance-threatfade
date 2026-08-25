from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest

from core.integrations import (
    ADAPTERS, Credential, DeliveryState, DeliveryAudit, IntegrationConfig,
    IntegrationEvent, IntegrationTransport, MemoryDeadLetterSink, RetryPolicy,
    StaticCredentialProvider,
)


class Response:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def event():
    return IntegrationEvent(
        event_id="evt-1", tenant_id="tenant-a", event_type="detection",
        observed_at=datetime(2026, 8, 25, tzinfo=timezone.utc), severity="high",
        confidence=0.91, title="C2 fade", description="fade observed",
        attack_techniques=("T1071",), sensor_id="sensor-1", detection_id="det-1",
    )


def config(name="elastic", endpoint="https://example.test/ingest"):
    return IntegrationConfig(name=name, endpoint=endpoint,
        credential_provider=StaticCredentialProvider(Credential("bearer", "secret")),
        retry_policy=RetryPolicy(max_attempts=3, base_delay_seconds=0, max_delay_seconds=0))


def test_all_requested_adapters_share_one_registry():
    assert set(ADAPTERS) == {"elastic", "sentinel", "qradar", "graylog", "wazuh", "misp", "opencti", "thehive", "soar"}
    for adapter in ADAPTERS.values():
        assert adapter.payload(event())


def test_normalized_event_has_deterministic_idempotency_key():
    assert event().idempotency_key == event().idempotency_key


def test_success_is_idempotent_and_does_not_repost():
    session = FakeSession([Response(202)])
    transport = IntegrationTransport(session=session, sleeper=lambda _: None)
    result = transport.deliver(event(), config())
    duplicate = transport.deliver(event(), config())
    assert result.state is DeliveryState.DELIVERED
    assert duplicate.state is DeliveryState.DUPLICATE
    assert len(session.calls) == 1
    assert session.calls[0]["headers"]["Idempotency-Key"] == event().idempotency_key


def test_retry_then_success():
    session = FakeSession([Response(503), Response(429, {"Retry-After": "0"}), Response(200)])
    transport = IntegrationTransport(session=session, sleeper=lambda _: None)
    result = transport.deliver(event(), config())
    assert result.state is DeliveryState.DELIVERED
    assert result.attempts == 3


def test_non_retryable_failure_goes_dead_letter():
    session = FakeSession([Response(400)])
    dlq = MemoryDeadLetterSink()
    transport = IntegrationTransport(session=session, dead_letter=dlq, sleeper=lambda _: None)
    result = transport.deliver(event(), config())
    assert result.state is DeliveryState.DEAD_LETTERED
    assert result.error_class == "http_400"
    assert len(dlq.items) == 1


def test_network_failure_is_bounded_and_audited():
    session = FakeSession([OSError("network down")] * 3)
    audit = DeliveryAudit()
    transport = IntegrationTransport(session=session, audit=audit, sleeper=lambda _: None)
    result = transport.deliver(event(), config())
    assert result.state is DeliveryState.DEAD_LETTERED
    assert result.attempts == 3
    assert audit.records[-1]["event_id"] == "evt-1"
    assert "secret" not in str(audit.records)


def test_real_http_mock_server_round_trip():
    seen = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            seen["path"] = self.path
            seen["headers"] = dict(self.headers)
            seen["body"] = self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(202)
            self.end_headers()

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = config(endpoint=f"http://127.0.0.1:{server.server_port}/ingest")
        result = IntegrationTransport(sleeper=lambda _: None).deliver(event(), cfg)
        assert result.state is DeliveryState.DELIVERED
        assert seen["path"] == "/ingest"
        assert seen["headers"]["Idempotency-Key"] == event().idempotency_key
        assert b"tenant-a" in seen["body"]
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_tenant_identity_is_in_payload():
    payload = ADAPTERS["elastic"].payload(event())
    assert payload["labels"]["tenant_id"] == "tenant-a"
    assert payload["threatfade"]["tenant_id"] == "tenant-a"


def test_https_tls_verification_cannot_be_disabled():
    with pytest.raises(ValueError):
        IntegrationConfig(name="elastic", endpoint="https://example.test", verify_tls=False,
                          credential_provider=StaticCredentialProvider(Credential()))


def test_http_endpoint_must_be_explicit():
    with pytest.raises(ValueError):
        IntegrationConfig(name="elastic", endpoint="example.test", credential_provider=StaticCredentialProvider(Credential()))


def test_unknown_integration_rejected():
    with pytest.raises(ValueError):
        IntegrationConfig(name="unknown", endpoint="https://example.test", credential_provider=StaticCredentialProvider(Credential()))


def test_hmac_credentials_are_not_logged():
    session = FakeSession([Response(200)])
    credential = Credential("hmac-sha256", "super-secret")
    transport = IntegrationTransport(session=session, sleeper=lambda _: None)
    result = transport.deliver(event(), IntegrationConfig("elastic", "https://example.test", StaticCredentialProvider(credential), retry_policy=RetryPolicy(max_attempts=1)))
    assert result.state is DeliveryState.DELIVERED
    assert "super-secret" not in str(transport.audit.records)
    assert session.calls[0]["headers"]["X-ThreatFade-Signature"]
