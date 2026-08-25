"""Normalized, auditable enterprise delivery for ThreatFade detections.

The module intentionally separates canonical ThreatFade events from destination
protocols. Credentials are supplied through providers and are never persisted
or rendered in delivery results/log records.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import socket
import ssl
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping, Protocol

import requests

LOGGER = logging.getLogger(__name__)


class DeliveryState(str, Enum):
    DELIVERED = "delivered"
    DUPLICATE = "duplicate"
    RETRYING = "retrying"
    FAILED = "failed"
    DEAD_LETTERED = "dead_lettered"


@dataclass(frozen=True)
class Credential:
    scheme: str = "none"
    value: str | None = None
    username: str | None = None
    password: str | None = None
    header: str = "Authorization"
    ca_bundle: str | None = None
    client_cert: str | None = None
    client_key: str | None = None


class CredentialProvider(Protocol):
    def current(self) -> Credential: ...


@dataclass
class StaticCredentialProvider:
    """Test/deployment adapter; production systems should inject a secret manager."""

    credential: Credential

    def current(self) -> Credential:
        return self.credential


@dataclass(frozen=True)
class IntegrationEvent:
    event_id: str
    tenant_id: str
    event_type: str
    observed_at: datetime
    severity: str
    confidence: float
    title: str
    description: str
    source: str = "threatfade"
    sensor_id: str | None = None
    detection_id: str | None = None
    session_id: str | None = None
    asset_id: str | None = None
    attack_techniques: tuple[str, ...] = ()
    evidence: tuple[Mapping[str, Any], ...] = ()
    provenance: tuple[Mapping[str, Any], ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id or not self.tenant_id:
            raise ValueError("event_id and tenant_id are required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")

    @property
    def idempotency_key(self) -> str:
        return hashlib.sha256(
            f"{self.tenant_id}:{self.event_id}".encode("utf-8")
        ).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "event_type": self.event_type,
            "observed_at": self.observed_at.astimezone(timezone.utc).isoformat(),
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "sensor_id": self.sensor_id,
            "detection_id": self.detection_id,
            "session_id": self.session_id,
            "asset_id": self.asset_id,
            "attack_techniques": list(self.attack_techniques),
            "evidence": [dict(x) for x in self.evidence],
            "provenance": [dict(x) for x in self.provenance],
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class DeliveryResult:
    integration: str
    event_id: str
    state: DeliveryState
    attempts: int
    status_code: int | None = None
    error_class: str | None = None
    dead_letter_reason: str | None = None
    latency_ms: float = 0.0


class DeadLetterSink(Protocol):
    def put(self, event: IntegrationEvent, reason: str) -> None: ...


@dataclass
class MemoryDeadLetterSink:
    items: list[tuple[IntegrationEvent, str]] = field(default_factory=list)

    def put(self, event: IntegrationEvent, reason: str) -> None:
        self.items.append((event, reason))


@dataclass
class DeliveryAudit:
    records: list[dict[str, Any]] = field(default_factory=list)

    def record(self, result: DeliveryResult) -> None:
        self.records.append({
            "integration": result.integration,
            "event_id": result.event_id,
            "state": result.state.value,
            "attempts": result.attempts,
            "status_code": result.status_code,
            "error_class": result.error_class,
            "dead_letter_reason": result.dead_letter_reason,
            "latency_ms": round(result.latency_ms, 3),
        })


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 4
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 10.0
    retry_statuses: frozenset[int] = frozenset({408, 425, 429, 500, 502, 503, 504})

    def delay(self, attempt: int) -> float:
        return min(self.max_delay_seconds, self.base_delay_seconds * (2 ** max(0, attempt - 1)))


class PayloadAdapter(Protocol):
    name: str
    def payload(self, event: IntegrationEvent) -> Any: ...
    def content_type(self) -> str: ...


def _ecs(event: IntegrationEvent) -> dict[str, Any]:
    return {
        "@timestamp": event.observed_at.astimezone(timezone.utc).isoformat(),
        "event": {
            "id": event.event_id,
            "kind": "alert",
            "category": ["network"],
            "type": [event.event_type],
            "severity": event.severity,
            "risk_score": round(event.confidence * 100, 2),
        },
        "message": event.description,
        "rule": {"name": event.title, "id": event.detection_id},
        "threat": {"technique": [{"id": x} for x in event.attack_techniques]},
        "observer": {"name": event.sensor_id},
        "host": {"id": event.asset_id},
        "network": {"session_id": event.session_id},
        "labels": {"tenant_id": event.tenant_id, "source": event.source},
        "threatfade": event.as_dict(),
    }


class ElasticAdapter:
    name = "elastic"
    def payload(self, event: IntegrationEvent) -> dict[str, Any]:
        return _ecs(event)
    def content_type(self) -> str:
        return "application/json"


class SentinelAdapter:
    name = "sentinel"
    def payload(self, event: IntegrationEvent) -> list[dict[str, Any]]:
        data = event.as_dict()
        data["ThreatFadeSeverity"] = event.severity
        data["ThreatFadeConfidence"] = event.confidence
        data["ThreatFadeTenantId"] = event.tenant_id
        return [data]
    def content_type(self) -> str:
        return "application/json"


class QRadarAdapter:
    name = "qradar"
    def payload(self, event: IntegrationEvent) -> str:
        # CEF is supported by QRadar DSMs and preserves a normalized subset.
        extension = {
            "externalId": event.event_id,
            "rt": event.observed_at.astimezone(timezone.utc).isoformat(),
            "msg": event.description,
            "cs1": event.tenant_id,
            "cs1Label": "ThreatFadeTenant",
            "cs2": str(round(event.confidence * 100, 2)),
            "cs2Label": "ThreatFadeConfidence",
        }
        ext = " ".join(f"{k}={str(v).replace('=', '_').replace(' ', '_')}" for k, v in extension.items())
        return f"CEF:0|ThreatFade|ThreatFade|1|{event.event_type}|{event.title}|{event.severity}|{ext}"
    def content_type(self) -> str:
        return "text/plain"


class GraylogAdapter:
    name = "graylog"
    def payload(self, event: IntegrationEvent) -> dict[str, Any]:
        data = event.as_dict()
        return {"version": "1.1", "host": event.sensor_id or "threatfade", "short_message": event.title,
                "full_message": event.description, "timestamp": event.observed_at.timestamp(),
                "level": {"low": 4, "medium": 5, "high": 6, "critical": 7}.get(event.severity.lower(), 5),
                "threatfade_event_id": event.event_id, "threatfade_tenant_id": event.tenant_id,
                "threatfade_confidence": event.confidence, "threatfade": data}
    def content_type(self) -> str:
        return "application/json"


class WazuhAdapter:
    name = "wazuh"
    def payload(self, event: IntegrationEvent) -> dict[str, Any]:
        return {"integration": "threatfade", "rule": {"id": event.detection_id or event.event_id,
                "description": event.title, "level": {"low": 4, "medium": 7, "high": 10, "critical": 13}.get(event.severity.lower(), 7)},
                "agent": {"id": event.sensor_id}, "data": event.as_dict()}
    def content_type(self) -> str:
        return "application/json"


class MISPAdapter:
    name = "misp"
    def payload(self, event: IntegrationEvent) -> dict[str, Any]:
        return {"Event": {"info": event.title, "distribution": "0", "published": False,
                "threat_level_id": {"low": "4", "medium": "3", "high": "2", "critical": "1"}.get(event.severity.lower(), "3"),
                "Tag": [{"name": f"threatfade:{x}"} for x in event.attack_techniques],
                "Attribute": [{"type": "comment", "category": "Other", "value": json.dumps(event.as_dict(), sort_keys=True)}]}}
    def content_type(self) -> str:
        return "application/json"


class OpenCTIAdapter:
    name = "opencti"
    def payload(self, event: IntegrationEvent) -> dict[str, Any]:
        # OpenCTI deployments commonly expose GraphQL; keep the mutation query
        # explicit so the deployment can validate it against its current schema.
        return {"query": "mutation ThreatFadeAlert($input: ThreatFadeAlertInput!) { threatFadeAlert(input: $input) { id } }",
                "variables": {"input": event.as_dict()}}
    def content_type(self) -> str:
        return "application/json"


class TheHiveAdapter:
    name = "thehive"
    def payload(self, event: IntegrationEvent) -> dict[str, Any]:
        return {"title": event.title, "description": event.description, "severity": {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(event.severity.lower(), 2),
                "source": "ThreatFade", "sourceRef": event.idempotency_key, "tags": [event.tenant_id, *event.attack_techniques],
                "customFields": {"threatfadeEventId": {"string": event.event_id}, "threatfadeConfidence": {"float": event.confidence}}}
    def content_type(self) -> str:
        return "application/json"


class SOARAdapter:
    name = "soar"
    def payload(self, event: IntegrationEvent) -> dict[str, Any]:
        return {"event": event.as_dict(), "idempotency_key": event.idempotency_key, "action": "threatfade.alert"}
    def content_type(self) -> str:
        return "application/json"


ADAPTERS: dict[str, PayloadAdapter] = {x.name: x for x in (
    ElasticAdapter(), SentinelAdapter(), QRadarAdapter(), GraylogAdapter(), WazuhAdapter(),
    MISPAdapter(), OpenCTIAdapter(), TheHiveAdapter(), SOARAdapter()
)}


@dataclass
class IntegrationConfig:
    name: str
    endpoint: str
    credential_provider: CredentialProvider
    timeout_seconds: float = 10.0
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    verify_tls: bool = True
    ca_bundle: str | None = None
    client_cert: tuple[str, str] | str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    max_response_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if self.name not in ADAPTERS:
            raise ValueError(f"unsupported integration: {self.name}")
        if not self.endpoint.startswith(("https://", "http://")):
            raise ValueError("endpoint must be an explicit HTTP(S) URL")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 120:
            raise ValueError("timeout_seconds must be >0 and <=120")
        if not self.verify_tls and self.endpoint.startswith("https://"):
            raise ValueError("TLS verification cannot be disabled for HTTPS integrations")


class IntegrationTransport:
    """Single delivery path for all HTTP integrations with safe retry semantics."""

    def __init__(self, audit: DeliveryAudit | None = None, dead_letter: DeadLetterSink | None = None,
                 session: requests.Session | None = None, sleeper: Callable[[float], None] = time.sleep) -> None:
        self.audit = audit or DeliveryAudit()
        self.dead_letter = dead_letter or MemoryDeadLetterSink()
        self.session = session or requests.Session()
        self.sleeper = sleeper
        self._delivered: set[str] = set()

    @staticmethod
    def _auth_headers(credential: Credential) -> dict[str, str]:
        if credential.scheme == "none":
            return {}
        if credential.scheme == "bearer" and credential.value:
            return {credential.header: f"Bearer {credential.value}"}
        if credential.scheme == "api-key" and credential.value:
            return {credential.header: credential.value}
        if credential.scheme == "hmac-sha256" and credential.value:
            # Caller receives the body hash and timestamp in transport; this scheme
            # is applied by _request below rather than leaking the secret to logs.
            return {}
        raise ValueError("invalid credential configuration")

    def deliver(self, event: IntegrationEvent, config: IntegrationConfig) -> DeliveryResult:
        started = time.monotonic()
        if event.idempotency_key in self._delivered:
            result = DeliveryResult(config.name, event.event_id, DeliveryState.DUPLICATE, 0, latency_ms=(time.monotonic()-started)*1000)
            self.audit.record(result)
            return result
        adapter = ADAPTERS[config.name]
        payload = adapter.payload(event)
        body = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"), sort_keys=True)
        credential = config.credential_provider.current()
        headers = {"Content-Type": adapter.content_type(), "Accept": "application/json", "Idempotency-Key": event.idempotency_key, **config.headers}
        headers.update(self._auth_headers(credential))
        if credential.scheme == "hmac-sha256" and credential.value:
            ts = str(int(time.time()))
            headers["X-ThreatFade-Timestamp"] = ts
            headers["X-ThreatFade-Signature"] = hmac.new(credential.value.encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
        attempts = 0
        last_error: str | None = None
        status_code: int | None = None
        for attempts in range(1, config.retry_policy.max_attempts + 1):
            try:
                response = self.session.post(config.endpoint, data=body.encode("utf-8"), headers=headers,
                                             timeout=config.timeout_seconds, verify=config.ca_bundle or config.verify_tls,
                                             cert=credential.client_cert or config.client_cert, allow_redirects=False)
                status_code = response.status_code
                if status_code in (200, 201, 202, 204, 409):
                    self._delivered.add(event.idempotency_key)
                    state = DeliveryState.DUPLICATE if status_code == 409 else DeliveryState.DELIVERED
                    result = DeliveryResult(config.name, event.event_id, state, attempts, status_code=status_code,
                                            latency_ms=(time.monotonic()-started)*1000)
                    self.audit.record(result)
                    return result
                if status_code not in config.retry_policy.retry_statuses:
                    last_error = f"http_{status_code}"
                    break
                last_error = f"http_{status_code}"
            except (requests.RequestException, ValueError) as exc:
                last_error = type(exc).__name__
            if attempts < config.retry_policy.max_attempts:
                retry_after = 0.0
                try:
                    retry_after = float(response.headers.get("Retry-After", "0")) if 'response' in locals() else 0.0
                except (TypeError, ValueError):
                    retry_after = 0.0
                self.sleeper(max(retry_after, config.retry_policy.delay(attempts)))
        result = DeliveryResult(config.name, event.event_id, DeliveryState.DEAD_LETTERED, attempts,
                                status_code=status_code, error_class=last_error, dead_letter_reason=last_error,
                                latency_ms=(time.monotonic()-started)*1000)
        self.dead_letter.put(event, last_error or "delivery_failed")
        self.audit.record(result)
        return result


def build_event(*, tenant_id: str, title: str, description: str, severity: str, confidence: float,
                event_type: str = "detection", **kwargs: Any) -> IntegrationEvent:
    return IntegrationEvent(event_id=str(uuid.uuid4()), tenant_id=tenant_id, event_type=event_type,
                            observed_at=datetime.now(timezone.utc), severity=severity, confidence=confidence,
                            title=title, description=description, **kwargs)
