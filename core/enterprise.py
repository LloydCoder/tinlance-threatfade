"""Enterprise identity, tenancy, authorization, audit and SLO primitives."""
from __future__ import annotations
import ipaddress, json, os, re, time, uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set
import requests
from fastapi import HTTPException, Request
try:
    import jwt
except ImportError:
    jwt = None
ROLES = {"viewer", "analyst", "admin", "tenant_admin", "api_only", "owner"}
ALLOWED_JWT_ALGORITHMS = {"RS256", "RS384", "RS512"}
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
SUBJECT_RE = re.compile(r"^.{1,255}$", re.DOTALL)
ROLE_PERMISSIONS = {"viewer": {"detection:read", "case:read"}, "analyst": {"detection:read", "detection:run", "case:read", "case:write", "export:write"}, "api_only": {"detection:run", "export:write"}, "admin": {"*"}, "tenant_admin": {"detection:read", "detection:run", "case:read", "case:write", "export:write", "org:read", "org:write", "member:write", "session:read", "session:write"}, "owner": {"*"}}
def _validated_identifier(value: Any, *, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value): raise HTTPException(403, f"Token has invalid {field}")
    return value
@dataclass(frozen=True)
class Principal:
    subject: str; tenant_id: str; roles: Set[str] = field(default_factory=set); scopes: Set[str] = field(default_factory=set); claims: Dict[str, Any] = field(default_factory=dict)
    @property
    def is_global_admin(self) -> bool:
        value = self.claims.get("global_admin")
        if value is None: value = self.claims.get("https://tinlance.com/global_admin")
        return value is True
    @property
    def auth_method(self) -> str: return str(self.claims.get("auth_method", "oidc"))
    def can(self, permission: str) -> bool:
        if "*" in self.scopes or permission in self.scopes: return True
        return any(permission in ROLE_PERMISSIONS.get(role, set()) or "*" in ROLE_PERMISSIONS.get(role, set()) for role in self.roles)
class OIDCValidator:
    def __init__(self):
        self.issuer = os.getenv("THREATFADE_OIDC_ISSUER", "").rstrip("/"); self.audience = os.getenv("THREATFADE_OIDC_AUDIENCE", ""); self.jwks_url = os.getenv("THREATFADE_OIDC_JWKS_URL", ""); self._jwks = None; self._jwks_at = 0.0
    @property
    def configured(self) -> bool: return bool(self.issuer and self.audience and (self.jwks_url or self.issuer))
    def _load_jwks(self):
        if self._jwks and time.monotonic() - self._jwks_at < 300: return self._jwks
        response = requests.get(self.jwks_url or f"{self.issuer}/.well-known/jwks.json", timeout=(2, 5), allow_redirects=False); response.raise_for_status(); payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list): raise ValueError("invalid JWKS document")
        self._jwks = payload; self._jwks_at = time.monotonic(); return payload
    def _key_for_token(self, token: str):
        header = jwt.get_unverified_header(token)
        if not isinstance(header, dict): raise ValueError("invalid JWT header")
        algorithm = header.get("alg")
        if algorithm not in ALLOWED_JWT_ALGORITHMS: raise ValueError("unsupported JWT algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 255: raise ValueError("missing or invalid key id")
        keys = self._load_jwks().get("keys", []); key = next((item for item in keys if item.get("kid") == kid), None)
        if not key:
            self._jwks = None; keys = self._load_jwks().get("keys", []); key = next((item for item in keys if item.get("kid") == kid), None)
        if not key or key.get("kty") != "RSA": raise ValueError("unknown or unsupported signing key")
        if key.get("use") not in (None, "sig") or key.get("alg") not in (None, algorithm): raise ValueError("JWKS key policy mismatch")
        return algorithm, jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    def validate(self, token: str) -> Principal:
        if not self.configured: raise HTTPException(503, "OIDC is not configured")
        if jwt is None: raise HTTPException(503, "PyJWT is required for OIDC authentication")
        if not isinstance(token, str) or not token or len(token) > 16384: raise HTTPException(401, "Invalid OIDC access token")
        try:
            algorithm, public_key = self._key_for_token(token)
            claims = jwt.decode(token, public_key, algorithms=[algorithm], audience=self.audience, issuer=self.issuer, options={"require": ["exp", "iat", "sub", "iss", "aud"], "verify_signature": True, "verify_exp": True, "verify_iat": True, "verify_iss": True, "verify_aud": True}, leeway=int(os.getenv("THREATFADE_OIDC_CLOCK_SKEW_SECONDS", "30")))
        except Exception as exc: raise HTTPException(401, "Invalid OIDC access token") from exc
        subject = _validated_identifier(claims.get("sub"), field="subject", pattern=SUBJECT_RE); tenant = claims.get("tenant_id") or claims.get("https://tinlance.com/tenant_id") or ""
        if tenant and not TENANT_RE.fullmatch(tenant): raise HTTPException(403, "Token has invalid tenant_id")
        raw_roles = claims.get("roles", []) or []; namespaced_roles = claims.get("https://tinlance.com/roles", []) or []
        if not isinstance(raw_roles, list) or not all(isinstance(role, str) for role in raw_roles) or not isinstance(namespaced_roles, list) or not all(isinstance(role, str) for role in namespaced_roles): raise HTTPException(403, "Token has invalid roles claim")
        roles = (set(raw_roles) | set(namespaced_roles)) & ROLES; raw_scope = claims.get("scope", "")
        if not isinstance(raw_scope, str) or len(raw_scope) > 4096: raise HTTPException(403, "Token has invalid scope claim")
        return Principal(subject, tenant, roles, {scope for scope in raw_scope.split() if scope}, claims)
OIDC = OIDCValidator()
def authenticate(request: Request, api_key: Optional[str] = None) -> Principal:
    authorization = request.headers.get("Authorization", "")
    if authorization:
        scheme, _, credentials = authorization.partition(" ")
        if scheme.lower() != "bearer" or not credentials.strip(): raise HTTPException(401, "Bearer authentication required")
        principal = OIDC.validate(credentials.strip()); session_token = request.headers.get("X-ThreatFade-Session")
        if session_token:
            from core.identity import validate_session
            if validate_session(session_token, principal.subject) is None: raise HTTPException(401, "Authentication session is no longer valid")
        from core.identity import ensure_user
        ensure_user(principal.subject, principal.claims.get("email"), principal.claims.get("name") or principal.claims.get("preferred_username")); return principal
    if os.getenv("THREATFADE_ENV", "development").lower() != "production":
        configured = os.getenv("THREATFADE_API_KEY")
        if configured and api_key == configured:
            tenant = request.headers.get("X-Tenant-ID", "local")
            if not TENANT_RE.fullmatch(tenant): raise HTTPException(400, "Invalid tenant identifier")
            return Principal("api-key", tenant, {"api_only"}, claims={"auth_method": "api_key"})
        if os.getenv("THREATFADE_ALLOW_DEV_AUTH", "true").lower() == "true":
            tenant = request.headers.get("X-Tenant-ID", "local")
            if not TENANT_RE.fullmatch(tenant): raise HTTPException(400, "Invalid tenant identifier")
            return Principal("local-development", tenant, {"admin"}, claims={"auth_method": "development", "global_admin": False})
    raise HTTPException(401, "Bearer OIDC token required in production")
def authorize(principal: Principal, permission: str):
    if not principal.can(permission): raise HTTPException(403, "Insufficient permissions")
def require_tenant(principal: Principal, tenant_id: Optional[str]) -> str:
    requested = tenant_id or principal.tenant_id
    if not requested:
        from core.identity import organizations_for
        orgs = organizations_for(principal.subject)
        if len(orgs) == 1: requested = orgs[0][0].id
        else: raise HTTPException(403, "Organization selection required")
    if not TENANT_RE.fullmatch(requested): raise HTTPException(400, "Invalid tenant identifier")
    from core.identity import membership
    member = membership(principal.subject, requested)
    if member is not None:
        principal.roles.clear(); principal.roles.add(member.role); return requested
    if os.getenv("THREATFADE_ENV", "development").lower() != "production" and requested == principal.tenant_id: return requested
    if not principal.is_global_admin and requested != principal.tenant_id: raise HTTPException(403, "Tenant access denied")
    if not principal.is_global_admin: raise HTTPException(403, "Tenant access denied")
    return requested
class AuditLogger:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.getenv("THREATFADE_AUDIT_PATH", "reports/audit/audit.jsonl"); directory = os.path.dirname(self.path)
        if directory: os.makedirs(directory, exist_ok=True)
    def record(self, action, principal: Principal, request: Optional[Request] = None, metadata: Optional[Dict[str, Any]] = None):
        client_ip = request.client.host if request and request.client else None
        try:
            if client_ip: ipaddress.ip_address(client_ip)
        except ValueError: client_ip = None
        event = {"event_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(), "action": action, "subject": principal.subject, "tenant_id": principal.tenant_id, "roles": sorted(principal.roles), "request_id": request.headers.get("X-Request-ID") if request else None, "source_ip": client_ip, "auth_method": principal.auth_method, "metadata": metadata or {}}
        with open(self.path, "a", encoding="utf-8") as handle: handle.write(json.dumps(event, sort_keys=True) + "\n")
AUDIT = AuditLogger()
def slo_targets(): return {"api_availability": os.getenv("THREATFADE_SLO_API_AVAILABILITY", "99.9%"), "p95_detection_latency": os.getenv("THREATFADE_SLO_P95_DETECTION_LATENCY", "<2s"), "p99_detection_latency": os.getenv("THREATFADE_SLO_P99_DETECTION_LATENCY", "<5s"), "recovery_time_objective": os.getenv("THREATFADE_SLO_RTO", "<60m"), "recovery_point_objective": os.getenv("THREATFADE_SLO_RPO", "<15m")}
