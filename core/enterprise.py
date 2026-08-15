"""Enterprise identity, tenancy, authorization, audit and SLO primitives.

The application accepts OIDC/OAuth2 bearer access tokens issued by a configured
enterprise IdP. API keys remain available only for local development or machine
clients explicitly configured for that purpose.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional, Set

import requests
from fastapi import HTTPException, Request

try:
    import jwt
except ImportError:  # pragma: no cover
    jwt = None


ROLES = {"viewer", "analyst", "admin", "tenant_admin", "api_only"}
ROLE_PERMISSIONS = {
    "viewer": {"detection:read", "case:read"},
    "analyst": {"detection:read", "detection:run", "case:read", "case:write", "export:write"},
    "api_only": {"detection:run", "export:write"},
    "admin": {"*"},
    "tenant_admin": {"*"},
}


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    roles: Set[str] = field(default_factory=set)
    scopes: Set[str] = field(default_factory=set)
    claims: Dict[str, Any] = field(default_factory=dict)

    def can(self, permission: str) -> bool:
        if "*" in self.scopes or "*" in self.roles:
            return True
        return any(permission in ROLE_PERMISSIONS.get(role, set()) or "*" in ROLE_PERMISSIONS.get(role, set()) for role in self.roles)


class OIDCValidator:
    def __init__(self) -> None:
        self.issuer = os.getenv("THREATFADE_OIDC_ISSUER", "").rstrip("/")
        self.audience = os.getenv("THREATFADE_OIDC_AUDIENCE", "")
        self.jwks_url = os.getenv("THREATFADE_OIDC_JWKS_URL", "")
        self._jwks: Optional[Dict[str, Any]] = None
        self._jwks_at = 0.0

    @property
    def configured(self) -> bool:
        return bool(self.issuer and self.audience and (self.jwks_url or self.issuer))

    def _load_jwks(self) -> Dict[str, Any]:
        if self._jwks and time.monotonic() - self._jwks_at < 300:
            return self._jwks
        url = self.jwks_url or f"{self.issuer}/.well-known/jwks.json"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        self._jwks = response.json()
        self._jwks_at = time.monotonic()
        return self._jwks

    def validate(self, token: str) -> Principal:
        if not self.configured:
            raise HTTPException(status_code=503, detail="OIDC is not configured")
        if jwt is None:
            raise HTTPException(status_code=503, detail="PyJWT is required for OIDC authentication")
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            key_data = next((k for k in self._load_jwks().get("keys", []) if k.get("kid") == kid), None)
            if not key_data:
                self._jwks = None
                key_data = next((k for k in self._load_jwks().get("keys", []) if k.get("kid") == kid), None)
            if not key_data:
                raise ValueError("unknown signing key")
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
            claims = jwt.decode(token, public_key, algorithms=["RS256", "RS384", "RS512"], audience=self.audience, issuer=self.issuer, options={"require": ["exp", "iat", "sub"]})
        except Exception as exc:
            raise HTTPException(status_code=401, detail="Invalid OIDC access token") from exc
        roles = set(claims.get("roles", [])) | set(claims.get("https://tinlance.com/roles", []))
        roles &= ROLES
        scopes = set(str(claims.get("scope", "")).split())
        tenant_id = claims.get("tenant_id") or claims.get("https://tinlance.com/tenant_id")
        if not tenant_id:
            raise HTTPException(status_code=403, detail="Token has no tenant_id claim")
        return Principal(str(claims["sub"]), str(tenant_id), roles, scopes, claims)


OIDC = OIDCValidator()


def authenticate(request: Request, api_key: Optional[str] = None) -> Principal:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return OIDC.validate(auth[7:].strip())
    # Local machine authentication is intentionally isolated from enterprise SSO.
    if os.getenv("THREATFADE_ENV", "development").lower() != "production":
        configured = os.getenv("THREATFADE_API_KEY")
        if configured and api_key == configured:
            return Principal("api-key", request.headers.get("X-Tenant-ID", "local"), {"api_only"})
        return Principal("local-development", request.headers.get("X-Tenant-ID", "local"), {"admin"})
    raise HTTPException(status_code=401, detail="Bearer OIDC token required in production")


def authorize(principal: Principal, permission: str) -> None:
    if not principal.can(permission):
        raise HTTPException(status_code=403, detail="Insufficient permissions")


def require_tenant(principal: Principal, tenant_id: Optional[str]) -> str:
    requested = tenant_id or principal.tenant_id
    if requested != principal.tenant_id and "admin" not in principal.roles and "tenant_admin" not in principal.roles:
        raise HTTPException(status_code=403, detail="Cross-tenant access denied")
    return requested


class AuditLogger:
    """Append-only JSON audit sink; production deployments should ship the file to immutable storage."""
    def __init__(self, path: str = "reports/audit/audit.jsonl") -> None:
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def record(self, action: str, principal: Principal, request: Optional[Request] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        event = {
            "event_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action, "subject": principal.subject, "tenant_id": principal.tenant_id,
            "roles": sorted(principal.roles), "request_id": request.headers.get("X-Request-ID") if request else None,
            "source_ip": request.client.host if request and request.client else None, "metadata": metadata or {},
        }
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")


AUDIT = AuditLogger()


def slo_targets() -> Dict[str, str]:
    return {
        "api_availability": os.getenv("THREATFADE_SLO_API_AVAILABILITY", "99.9%"),
        "p95_detection_latency": os.getenv("THREATFADE_SLO_P95_DETECTION_LATENCY", "<2s"),
        "p99_detection_latency": os.getenv("THREATFADE_SLO_P99_DETECTION_LATENCY", "<5s"),
        "recovery_time_objective": os.getenv("THREATFADE_SLO_RTO", "<60m"),
        "recovery_point_objective": os.getenv("THREATFADE_SLO_RPO", "<15m"),
    }
