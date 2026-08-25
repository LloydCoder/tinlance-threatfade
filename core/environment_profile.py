"""Tenant-scoped environment profiles for adaptive ThreatFade baselines.

Profiles describe observed/expected operating conditions; they do not classify
unauthorized behavior as malicious. Detection still requires independent
security evidence.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Optional, Tuple

SCHEMA_VERSION = "1.0"


def _text(value: str, name: str, limit: int = 255) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError(f"invalid {name}")
    return value


def _nonnegative(value: float, name: str) -> float:
    if not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"invalid {name}")
    return float(value)


@dataclass(frozen=True)
class SensitivityThresholds:
    entropy_zscore: float = 3.0
    periodicity_score: float = 0.8
    destination_deviation: float = 0.5

    def __post_init__(self) -> None:
        _nonnegative(self.entropy_zscore, "entropy_zscore")
        if not 0 <= self.periodicity_score <= 1:
            raise ValueError("periodicity_score must be between 0 and 1")
        if not 0 <= self.destination_deviation <= 1:
            raise ValueError("destination_deviation must be between 0 and 1")


@dataclass(frozen=True)
class EnvironmentProfile:
    profile_id: str
    tenant_id: str
    version: int
    name: str
    expected_protocols: Tuple[str, ...] = ()
    expected_ports: Tuple[int, ...] = ()
    baseline_entropy: Mapping[str, float] = field(default_factory=dict)
    baseline_periodicity: Mapping[str, float] = field(default_factory=dict)
    expected_destinations: Tuple[str, ...] = ()
    sensitivity: SensitivityThresholds = field(default_factory=SensitivityThresholds)
    allowed_integrations: Tuple[str, ...] = ()
    retention_seconds: int = 30 * 86400
    deployment_constraints: Mapping[str, str] = field(default_factory=dict)
    status: str = "active"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _text(self.profile_id, "profile_id", 128)
        _text(self.tenant_id, "tenant_id")
        _text(self.name, "name")
        _text(self.created_by, "created_by", 128)
        if not isinstance(self.version, int) or self.version < 1:
            raise ValueError("version must be positive")
        if self.status not in {"draft", "active", "rolled_back", "retired"}:
            raise ValueError("invalid profile status")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if not isinstance(self.retention_seconds, int) or not 3600 <= self.retention_seconds <= 31_536_000:
            raise ValueError("retention_seconds outside permitted bounds")
        if len(self.expected_ports) > 1024 or any(not isinstance(p, int) or not 0 <= p <= 65535 for p in self.expected_ports):
            raise ValueError("invalid expected_ports")
        if len(self.expected_protocols) > 128 or any(not isinstance(p, str) or not p for p in self.expected_protocols):
            raise ValueError("invalid expected_protocols")
        if len(self.expected_destinations) > 4096 or any(not isinstance(d, str) or not d or len(d) > 255 for d in self.expected_destinations):
            raise ValueError("invalid expected_destinations")
        for mapping_name, values in (("baseline_entropy", self.baseline_entropy), ("baseline_periodicity", self.baseline_periodicity)):
            if len(values) > 256:
                raise ValueError(f"{mapping_name} too large")
            for key, value in values.items():
                _text(key, f"{mapping_name} key", 128)
                _nonnegative(value, f"{mapping_name} value")
        if len(self.allowed_integrations) > 128 or any(not isinstance(v, str) or not v for v in self.allowed_integrations):
            raise ValueError("invalid allowed_integrations")
        if len(self.deployment_constraints) > 64:
            raise ValueError("deployment_constraints too large")

    def canonical_dict(self) -> dict:
        data = asdict(self)
        data["created_at"] = self.created_at.astimezone(timezone.utc).isoformat()
        data["expected_protocols"] = list(self.expected_protocols)
        data["expected_ports"] = list(self.expected_ports)
        data["expected_destinations"] = list(self.expected_destinations)
        data["allowed_integrations"] = list(self.allowed_integrations)
        return data

    def digest(self) -> str:
        payload = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(payload).hexdigest()


class ProfileStore:
    """In-memory reference store enforcing tenant isolation and immutable versions."""

    def __init__(self) -> None:
        self._profiles: dict[tuple[str, str, int], EnvironmentProfile] = {}
        self._active: dict[tuple[str, str], int] = {}
        self._audit: list[dict] = []

    def put(self, profile: EnvironmentProfile, *, actor_tenant: str) -> EnvironmentProfile:
        _text(actor_tenant, "actor_tenant")
        if actor_tenant != profile.tenant_id:
            raise PermissionError("tenant mismatch")
        key = (profile.tenant_id, profile.profile_id, profile.version)
        if key in self._profiles:
            raise ValueError("profile version already exists")
        latest = max((v for (t, p, v) in self._profiles if t == profile.tenant_id and p == profile.profile_id), default=0)
        if profile.version != latest + 1:
            raise ValueError("profile version must advance monotonically")
        self._profiles[key] = profile
        self._audit.append({"action": "create", "tenant_id": profile.tenant_id, "profile_id": profile.profile_id, "version": profile.version, "digest": profile.digest(), "actor_tenant": actor_tenant})
        if profile.status == "active":
            self.activate(profile.tenant_id, profile.profile_id, profile.version, actor_tenant=actor_tenant)
        return profile

    def activate(self, tenant_id: str, profile_id: str, version: int, *, actor_tenant: str) -> EnvironmentProfile:
        if actor_tenant != tenant_id:
            raise PermissionError("tenant mismatch")
        key = (tenant_id, profile_id, version)
        profile = self._profiles.get(key)
        if not profile or profile.status in {"retired", "rolled_back"}:
            raise ValueError("profile version cannot be activated")
        old = self._active.get((tenant_id, profile_id))
        self._active[(tenant_id, profile_id)] = version
        self._audit.append({"action": "activate", "tenant_id": tenant_id, "profile_id": profile_id, "version": version, "previous_version": old, "actor_tenant": actor_tenant})
        return profile

    def rollback(self, tenant_id: str, profile_id: str, version: int, *, actor_tenant: str) -> EnvironmentProfile:
        if actor_tenant != tenant_id:
            raise PermissionError("tenant mismatch")
        key = (tenant_id, profile_id, version)
        profile = self._profiles.get(key)
        if not profile:
            raise KeyError(key)
        self._active[(tenant_id, profile_id)] = version
        self._audit.append({"action": "rollback", "tenant_id": tenant_id, "profile_id": profile_id, "version": version, "actor_tenant": actor_tenant})
        return profile

    def active(self, tenant_id: str, profile_id: str, *, actor_tenant: str) -> Optional[EnvironmentProfile]:
        if actor_tenant != tenant_id:
            raise PermissionError("tenant mismatch")
        version = self._active.get((tenant_id, profile_id))
        return self._profiles.get((tenant_id, profile_id, version)) if version else None

    def audit(self, tenant_id: str, *, actor_tenant: str) -> list[dict]:
        if actor_tenant != tenant_id:
            raise PermissionError("tenant mismatch")
        return [dict(x) for x in self._audit if x["tenant_id"] == tenant_id]


def validate_profile(profile: EnvironmentProfile) -> None:
    if not isinstance(profile, EnvironmentProfile):
        raise TypeError("expected EnvironmentProfile")
    if profile.schema_version != SCHEMA_VERSION:
        raise ValueError("unsupported profile schema version")
