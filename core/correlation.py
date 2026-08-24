"""Reusable multi-domain temporal correlation primitives.

The correlation layer consumes canonical ``SignalEvent`` observations and
produces evidence-backed correlated detections. It is deliberately domain
agnostic: GNSS, network, endpoint, RF, timing and sensor-health signals are
represented by the same observation contract.

A correlation is an observed temporal association, not causal attribution.
Missing, duplicated, conflicting, skewed and out-of-order telemetry are
handled explicitly and never silently converted into stronger evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
from typing import Any, Iterable, Mapping, Sequence
from uuid import NAMESPACE_URL, uuid5

from .data_plane import SignalEvent
from .integrity import evidence_custody_hash

CORRELATION_SCHEMA_VERSION = "1.0"
DEFAULT_WINDOW_SECONDS = 30.0
DEFAULT_CLOCK_SKEW_SECONDS = 5.0
DEFAULT_THRESHOLD = 0.65


def _clip(value: float) -> float:
    return float(max(0.0, min(1.0, value)))


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


def _finite_score(value: Any, name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be within [0, 1]")
    return result


@dataclass(frozen=True)
class CorrelationObservation:
    """Normalized observation derived from a canonical SignalEvent."""

    event_id: str
    tenant_id: str
    sensor_id: str
    domain: str
    signal_type: str
    signal_score: float
    sensor_confidence: float
    uncertainty: float
    observed_at: datetime
    event_digest: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id or not self.tenant_id or not self.sensor_id:
            raise ValueError("event, tenant and sensor identifiers are required")
        if not self.domain or not self.signal_type:
            raise ValueError("domain and signal_type are required")
        _finite_score(self.signal_score, "signal_score")
        _finite_score(self.sensor_confidence, "sensor_confidence")
        _finite_score(self.uncertainty, "uncertainty")
        _utc(self.observed_at)
        if len(self.event_digest) != 64 or any(c not in "0123456789abcdef" for c in self.event_digest.lower()):
            raise ValueError("event_digest must be SHA-256 hex")

    @property
    def effective_score(self) -> float:
        """Signal strength discounted by explicitly reported uncertainty."""
        return _clip(self.signal_score * self.sensor_confidence * (1.0 - self.uncertainty))

    @classmethod
    def from_event(
        cls,
        event: SignalEvent,
        *,
        domain: str,
        signal_type: str,
        signal_score: float,
        sensor_confidence: float = 1.0,
        uncertainty: float = 0.0,
        metadata: Mapping[str, Any] | None = None,
    ) -> "CorrelationObservation":
        if not isinstance(event, SignalEvent):
            raise TypeError("event must be SignalEvent")
        return cls(
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            sensor_id=event.sensor_id,
            domain=domain,
            signal_type=signal_type,
            signal_score=_finite_score(signal_score, "signal_score"),
            sensor_confidence=_finite_score(sensor_confidence, "sensor_confidence"),
            uncertainty=_finite_score(uncertainty, "uncertainty"),
            observed_at=_utc(event.observed_at),
            event_digest=event.digest(),
            metadata=dict(metadata or {}),
        )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "sensor_id": self.sensor_id,
            "domain": self.domain,
            "signal_type": self.signal_type,
            "signal_score": self.signal_score,
            "sensor_confidence": self.sensor_confidence,
            "uncertainty": self.uncertainty,
            "observed_at": _utc(self.observed_at).isoformat(),
            "event_digest": self.event_digest,
            "metadata": dict(sorted(self.metadata.items())),
        }


@dataclass(frozen=True)
class CorrelationPolicy:
    """Explicit, auditable correlation policy."""

    window_seconds: float = DEFAULT_WINDOW_SECONDS
    max_clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS
    threshold: float = DEFAULT_THRESHOLD
    min_signal_score: float = 0.50
    min_domains: int = 2

    def __post_init__(self) -> None:
        for name, value in (("window_seconds", self.window_seconds), ("max_clock_skew_seconds", self.max_clock_skew_seconds)):
            if not math.isfinite(float(value)) or float(value) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.max_clock_skew_seconds > self.window_seconds:
            raise ValueError("clock skew cannot exceed correlation window")
        for name, value in (("threshold", self.threshold), ("min_signal_score", self.min_signal_score)):
            _finite_score(value, name)
        if self.min_domains < 2:
            raise ValueError("min_domains must be at least 2")


@dataclass(frozen=True)
class CorrelatedDetection:
    """Evidence-backed result of temporal multi-domain corroboration."""

    correlation_id: str
    tenant_id: str
    rule_id: str
    observation_ids: tuple[str, ...]
    domains: tuple[str, ...]
    signal_types: tuple[str, ...]
    confidence: float
    temporal_delta_ms: int
    temporal_score: float
    signal_score: float
    sensor_confidence: float
    correlation_strength: float
    clock_skew_tolerance_ms: int
    missing_domains: tuple[str, ...]
    duplicate_event_ids: tuple[str, ...]
    out_of_order_count: int
    attribution: str
    causal_attribution: str
    evidence_hash: str
    generated_at: datetime
    schema_version: str = CORRELATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.attribution != "observed_correlation":
            raise ValueError("attribution must explicitly identify observed correlation")
        if self.causal_attribution != "not_established":
            raise ValueError("causal attribution is not established by this engine")
        for name, value in (("confidence", self.confidence), ("temporal_score", self.temporal_score), ("signal_score", self.signal_score), ("sensor_confidence", self.sensor_confidence), ("correlation_strength", self.correlation_strength)):
            _finite_score(value, name)
        if self.temporal_delta_ms < 0 or self.clock_skew_tolerance_ms < 0:
            raise ValueError("temporal values cannot be negative")
        if len(self.evidence_hash) != 64:
            raise ValueError("evidence_hash must be SHA-256 hex")

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "correlation_id": self.correlation_id,
            "tenant_id": self.tenant_id,
            "rule_id": self.rule_id,
            "observation_ids": list(self.observation_ids),
            "domains": list(self.domains),
            "signal_types": list(self.signal_types),
            "confidence": self.confidence,
            "temporal_delta_ms": self.temporal_delta_ms,
            "temporal_score": self.temporal_score,
            "signal_score": self.signal_score,
            "sensor_confidence": self.sensor_confidence,
            "correlation_strength": self.correlation_strength,
            "clock_skew_tolerance_ms": self.clock_skew_tolerance_ms,
            "missing_domains": list(self.missing_domains),
            "duplicate_event_ids": list(self.duplicate_event_ids),
            "out_of_order_count": self.out_of_order_count,
            "attribution": self.attribution,
            "causal_attribution": self.causal_attribution,
            "evidence_hash": self.evidence_hash,
            "generated_at": _utc(self.generated_at).isoformat(),
        }


class TemporalCorrelationEngine:
    """Deterministic pairwise/multi-domain temporal corroboration engine."""

    def __init__(self, policy: CorrelationPolicy | None = None):
        self.policy = policy or CorrelationPolicy()

    def correlate(
        self,
        observations: Sequence[CorrelationObservation] | Iterable[CorrelationObservation],
        *,
        required_domains: Sequence[str] | None = None,
        rule_id: str = "TF-CORR-001",
        generated_at: datetime | None = None,
    ) -> list[CorrelatedDetection]:
        items = list(observations)
        if any(not isinstance(item, CorrelationObservation) for item in items):
            raise TypeError("all observations must be CorrelationObservation")
        if not items:
            return []

        seen: set[str] = set()
        duplicates: list[str] = []
        unique: list[CorrelationObservation] = []
        for item in items:
            if item.event_id in seen:
                duplicates.append(item.event_id)
                continue
            seen.add(item.event_id)
            unique.append(item)

        ordered = sorted(unique, key=lambda item: (item.observed_at, item.event_id))
        out_of_order = sum(1 for left, right in zip(unique, unique[1:]) if left.observed_at > right.observed_at)
        domains_required = tuple(sorted(set(required_domains or [])))
        if domains_required and len(domains_required) < self.policy.min_domains:
            raise ValueError("required_domains must contain at least two domains")

        results: list[CorrelatedDetection] = []
        for anchor in ordered:
            if anchor.signal_score < self.policy.min_signal_score:
                continue
            candidates = [
                item
                for item in ordered
                if item.event_id != anchor.event_id
                and item.tenant_id == anchor.tenant_id
                and item.domain != anchor.domain
                and item.signal_score >= self.policy.min_signal_score
                and abs((item.observed_at - anchor.observed_at).total_seconds()) <= self.policy.window_seconds
            ]
            if not candidates:
                continue
            candidates.sort(key=lambda item: (abs((item.observed_at - anchor.observed_at).total_seconds()), item.event_id))
            candidate_domains: dict[str, CorrelationObservation] = {anchor.domain: anchor}
            for item in candidates:
                candidate_domains.setdefault(item.domain, item)
            if len(candidate_domains) < self.policy.min_domains:
                continue
            if domains_required and not set(domains_required).issubset(candidate_domains):
                continue

            selected = tuple(sorted(candidate_domains.values(), key=lambda item: (item.observed_at, item.event_id)))
            if len(selected) < self.policy.min_domains:
                continue
            timestamps = [item.observed_at for item in selected]
            delta = (max(timestamps) - min(timestamps)).total_seconds()
            temporal_score = _clip(1.0 - delta / self.policy.window_seconds)
            signal_score = _clip(sum(item.signal_score for item in selected) / len(selected))
            sensor_confidence = _clip(sum(item.sensor_confidence * (1.0 - item.uncertainty) for item in selected) / len(selected))
            effective = [item.effective_score for item in selected]
            correlation_strength = _clip(math.sqrt(math.prod(effective)) if effective else 0.0)
            confidence = _clip(0.35 * temporal_score + 0.30 * signal_score + 0.20 * sensor_confidence + 0.15 * correlation_strength)
            if confidence < self.policy.threshold:
                continue

            evidence_payload = {
                "rule_id": rule_id,
                "tenant_id": anchor.tenant_id,
                "observation_ids": [item.event_id for item in selected],
                "event_digests": [item.event_digest for item in selected],
                "domains": sorted({item.domain for item in selected}),
                "signal_types": sorted({item.signal_type for item in selected}),
                "temporal_delta_ms": int(round(delta * 1000)),
                "temporal_score": temporal_score,
                "signal_score": signal_score,
                "sensor_confidence": sensor_confidence,
                "correlation_strength": correlation_strength,
                "attribution": "observed_correlation",
                "causal_attribution": "not_established",
            }
            evidence_hash = hashlib.sha256(json.dumps(evidence_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            correlation_id = uuid5(NAMESPACE_URL, evidence_hash).hex
            generated = _utc(generated_at or datetime.now(timezone.utc))
            result = CorrelatedDetection(
                correlation_id=correlation_id,
                tenant_id=anchor.tenant_id,
                rule_id=rule_id,
                observation_ids=tuple(item.event_id for item in selected),
                domains=tuple(sorted({item.domain for item in selected})),
                signal_types=tuple(sorted({item.signal_type for item in selected})),
                confidence=confidence,
                temporal_delta_ms=int(round(delta * 1000)),
                temporal_score=temporal_score,
                signal_score=signal_score,
                sensor_confidence=sensor_confidence,
                correlation_strength=correlation_strength,
                clock_skew_tolerance_ms=int(round(self.policy.max_clock_skew_seconds * 1000)),
                missing_domains=tuple(sorted(set(domains_required) - set(candidate_domains))) if domains_required else (),
                duplicate_event_ids=tuple(sorted(set(duplicates))),
                out_of_order_count=out_of_order,
                attribution="observed_correlation",
                causal_attribution="not_established",
                evidence_hash=evidence_hash,
                generated_at=generated,
            )
            if not any(existing.correlation_id == result.correlation_id for existing in results):
                results.append(result)
        return results


def evidence_custody_record(detection: CorrelatedDetection, *, previous_hash: str = "0" * 64) -> dict[str, Any]:
    """Create a verifiable custody record for a correlated detection."""
    content = json.dumps(detection.canonical_dict(), sort_keys=True, separators=(",", ":")).encode()
    content_sha256 = hashlib.sha256(content).hexdigest()
    custody_hash = evidence_custody_hash(
        previous_hash=previous_hash,
        tenant_id=detection.tenant_id,
        correlation_id=detection.correlation_id,
        evidence_type="multi_domain_correlation",
        content_sha256=content_sha256,
        size_bytes=len(content),
        source_uri=None,
        collected_at=detection.generated_at.isoformat(),
    )
    return {
        "correlation_id": detection.correlation_id,
        "tenant_id": detection.tenant_id,
        "evidence_type": "multi_domain_correlation",
        "content_sha256": content_sha256,
        "previous_hash": previous_hash,
        "custody_hash": custody_hash,
        "attribution": "observed_correlation",
        "causal_attribution": "not_established",
    }
