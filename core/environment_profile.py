"""Tenant-scoped environment profiles and observation/authorization context.

Profiles are configuration context only. A mismatch is not a maliciousness verdict.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Optional, Tuple

SCHEMA_VERSION = "1.1"
MAX_LIST = 4096


def _text(value: str, name: str, limit: int = 255) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError(f"invalid {name}")
    return value


def _number(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"invalid {name}")
    value = float(value)
    if value != value or value in (float("inf"), float("-inf")) or value < 0:
        raise ValueError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class SensitivityThresholds:
    entropy_zscore: float = 3.0
    periodicity_score: float = 0.8
    destination_deviation: float = 0.5

    def __post_init__(self) -> None:
        _number(self.entropy_zscore, "entropy_zscore")
        if not 0 <= self.periodicity_score <= 1 or not 0 <= self.destination_deviation <= 1:
            raise ValueError("bounded sensitivity threshold")


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
    status: str = "draft"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _text(self.profile_id, "profile_id", 128); _text(self.tenant_id, "tenant_id"); _text(self.name, "name"); _text(self.created_by, "created_by", 128)
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1: raise ValueError("version must be positive")
        if self.status not in {"draft", "active", "retired"}: raise ValueError("invalid profile status")
        if self.schema_version != SCHEMA_VERSION: raise ValueError("unsupported profile schema version")
        if self.created_at.tzinfo is None: raise ValueError("created_at must be timezone-aware")
        if not isinstance(self.retention_seconds, int) or not 3600 <= self.retention_seconds <= 31_536_000: raise ValueError("retention_seconds outside bounds")
        if len(self.expected_ports) > 1024 or any(isinstance(p, bool) or not isinstance(p, int) or not 0 <= p <= 65535 for p in self.expected_ports): raise ValueError("invalid expected_ports")
        if len(self.expected_protocols) > 128 or any(not isinstance(p, str) or not p or len(p) > 64 for p in self.expected_protocols): raise ValueError("invalid expected_protocols")
        if len(self.expected_destinations) > MAX_LIST or any(not isinstance(d, str) or not d or len(d) > 255 for d in self.expected_destinations): raise ValueError("invalid expected_destinations")
        for name, values in (("baseline_entropy", self.baseline_entropy), ("baseline_periodicity", self.baseline_periodicity)):
            if not isinstance(values, Mapping) or len(values) > 256: raise ValueError(f"invalid {name}")
            for key, value in values.items(): _text(key, f"{name} key", 128); _number(value, f"{name} value")
        if len(self.allowed_integrations) > 128 or any(not isinstance(v, str) or not v for v in self.allowed_integrations): raise ValueError("invalid allowed_integrations")
        if len(self.deployment_constraints) > 64: raise ValueError("deployment_constraints too large")

    def canonical_dict(self) -> dict:
        data = asdict(self)
        data["created_at"] = self.created_at.astimezone(timezone.utc).isoformat()
        for key in ("expected_protocols", "expected_ports", "expected_destinations", "allowed_integrations"):
            data[key] = sorted(data[key])
        data["baseline_entropy"] = dict(sorted(data["baseline_entropy"].items()))
        data["baseline_periodicity"] = dict(sorted(data["baseline_periodicity"].items()))
        data["deployment_constraints"] = dict(sorted(data["deployment_constraints"].items()))
        return data

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class ObservationContext:
    """What the sensor actually observed; independent from authorization."""
    protocol: Optional[str] = None
    port: Optional[int] = None
    destination: Optional[str] = None
    entropy: Optional[float] = None
    periodicity: Optional[float] = None


@dataclass(frozen=True)
class AuthorizationAssessment:
    """Context comparison only; never a maliciousness verdict."""
    deviations: Tuple[str, ...]
    evidence_required: bool = True

    @property
    def authorized(self) -> bool:
        return not self.deviations


def assess_authorization(profile: EnvironmentProfile, observation: ObservationContext) -> AuthorizationAssessment:
    deviations: list[str] = []
    if observation.protocol and profile.expected_protocols and observation.protocol not in profile.expected_protocols: deviations.append("protocol")
    if observation.port is not None and profile.expected_ports and observation.port not in profile.expected_ports: deviations.append("port")
    if observation.destination and profile.expected_destinations and observation.destination not in profile.expected_destinations: deviations.append("destination")
    if observation.entropy is not None and observation.protocol in profile.baseline_entropy:
        if abs(float(observation.entropy) - profile.baseline_entropy[observation.protocol]) > profile.sensitivity.entropy_zscore: deviations.append("entropy")
    if observation.periodicity is not None and observation.protocol in profile.baseline_periodicity:
        if abs(float(observation.periodicity) - profile.baseline_periodicity[observation.protocol]) > profile.sensitivity.periodicity_score: deviations.append("periodicity")
    return AuthorizationAssessment(tuple(sorted(set(deviations))))


class ProfileStore:
    """Reference lifecycle store. Production persistence is tenant-scoped via DB RLS."""
    def __init__(self) -> None:
        self._profiles: dict[tuple[str, str, int], EnvironmentProfile] = {}
        self._active: dict[tuple[str, str], int] = {}
        self._audit: list[dict] = []

    def put(self, profile: EnvironmentProfile, *, actor_tenant: str) -> EnvironmentProfile:
        if actor_tenant != profile.tenant_id: raise PermissionError("tenant mismatch")
        validate_profile(profile)
        key = (profile.tenant_id, profile.profile_id, profile.version)
        if key in self._profiles: raise ValueError("profile version already exists")
        versions = [v for (t, p, v) in self._profiles if t == profile.tenant_id and p == profile.profile_id]
        if profile.version != (max(versions, default=0) + 1): raise ValueError("profile version must advance monotonically")
        if profile.status == "active" and (profile.tenant_id, profile.profile_id) in self._active: raise ValueError("active profile conflict; activate explicitly")
        self._profiles[key] = profile
        self._record("create", profile, actor_tenant)
        if profile.status == "active": self.activate(profile.tenant_id, profile.profile_id, profile.version, actor_tenant=actor_tenant)
        return profile

    def activate(self, tenant_id: str, profile_id: str, version: int, *, actor_tenant: str) -> EnvironmentProfile:
        if actor_tenant != tenant_id: raise PermissionError("tenant mismatch")
        profile = self._profiles.get((tenant_id, profile_id, version))
        if not profile or profile.status == "retired": raise ValueError("profile version cannot be activated")
        previous = self._active.get((tenant_id, profile_id))
        self._active[(tenant_id, profile_id)] = version
        self._record("activate", profile, actor_tenant, previous_version=previous)
        return profile

    def rollback(self, tenant_id: str, profile_id: str, version: int, *, actor_tenant: str) -> EnvironmentProfile:
        if actor_tenant != tenant_id: raise PermissionError("tenant mismatch")
        profile = self._profiles.get((tenant_id, profile_id, version))
        if not profile: raise KeyError((tenant_id, profile_id, version))
        previous = self._active.get((tenant_id, profile_id))
        if previous == version: raise ValueError("rollback target is already active")
        self._active[(tenant_id, profile_id)] = version
        self._record("rollback", profile, actor_tenant, previous_version=previous)
        return profile

    def active(self, tenant_id: str, profile_id: str, *, actor_tenant: str) -> Optional[EnvironmentProfile]:
        if actor_tenant != tenant_id: raise PermissionError("tenant mismatch")
        version = self._active.get((tenant_id, profile_id))
        return self._profiles.get((tenant_id, profile_id, version)) if version else None

    def audit(self, tenant_id: str, *, actor_tenant: str) -> list[dict]:
        if actor_tenant != tenant_id: raise PermissionError("tenant mismatch")
        return [dict(x) for x in self._audit if x["tenant_id"] == tenant_id]

    def _record(self, action: str, profile: EnvironmentProfile, actor_tenant: str, **extra: object) -> None:
        self._audit.append({"action": action, "tenant_id": profile.tenant_id, "profile_id": profile.profile_id, "version": profile.version, "digest": profile.digest(), "actor_tenant": actor_tenant, **extra})


def validate_profile(profile: EnvironmentProfile) -> None:
    if not isinstance(profile, EnvironmentProfile): raise TypeError("expected EnvironmentProfile")
    if profile.schema_version != SCHEMA_VERSION: raise ValueError("unsupported profile schema version")
    if len(set(profile.expected_protocols)) != len(profile.expected_protocols): raise ValueError("duplicate expected protocol")
    if len(set(profile.expected_ports)) != len(profile.expected_ports): raise ValueError("duplicate expected port")
    if len(set(profile.expected_destinations)) != len(profile.expected_destinations): raise ValueError("duplicate expected destination")
