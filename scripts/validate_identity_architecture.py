#!/usr/bin/env python3
"""Deterministic architecture gate for ThreatFade identity and tenancy controls."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTERPRISE = (ROOT / "core" / "enterprise.py").read_text(encoding="utf-8")
IDENTITY = (ROOT / "core" / "identity.py").read_text(encoding="utf-8")
ROUTES = (ROOT / "core" / "identity_routes.py").read_text(encoding="utf-8")

REQUIRED = {
    "production OIDC boundary": 'raise HTTPException(401, "Bearer OIDC token required in production")',
    "RSA algorithm allowlist": "ALLOWED_JWT_ALGORITHMS = {\"RS256\", \"RS384\", \"RS512\"}",
    "issuer validation": 'issuer=self.issuer',
    "audience validation": 'audience=self.audience',
    "required JWT claims": '"exp", "iat", "sub", "iss", "aud"',
    "optional tenant claim support": 'or ""',
    "membership resolution": "membership(principal.subject, requested)",
    "deny cross-tenant": 'raise HTTPException(403, "Tenant access denied")',
    "explicit global admin": "principal.is_global_admin",
    "bounded JWKS request": "timeout=(2, 5)",
    "redirect refusal": "allow_redirects=False",
    "session validation": "validate_session(session_token, principal.subject)",
    "random session token": "secrets.token_urlsafe(32)",
    "verified invitation email": "principal.claims.get(\"email\")",
}


def fail(message: str) -> None:
    raise SystemExit(f"identity architecture validation failed: {message}")


def main() -> None:
    for name, marker in REQUIRED.items():
        if name == "random session token":
            haystack = IDENTITY
        elif name == "verified invitation email":
            haystack = ROUTES
        else:
            haystack = ENTERPRISE
        if marker not in haystack:
            fail(f"missing {name}: {marker}")
    if "APIRouter(prefix=\"/enterprise/identity\"" not in ROUTES or "def organization_create" not in ROUTES:
        fail("identity routes are not mounted")
    if "class InvitationAccept" not in ROUTES or "email:" in ROUTES.split("class InvitationAccept", 1)[1].split("@router.post", 1)[0]:
        fail("invitation acceptance accepts caller-supplied email instead of verified identity")
    if 'payload.email' in ROUTES.split('@router.post("/invitations/accept")', 1)[1].split('@router.patch', 1)[0]:
        fail("invitation acceptance trusts a caller-supplied email")
    if 'authorization.startswith("Bearer ")' in ENTERPRISE:
        fail("legacy case-sensitive Bearer parser remains")
    if 'requested != principal.tenant_id and "admin" not in principal.roles' in ENTERPRISE:
        fail("admin role can cross tenant boundaries without explicit global delegation")
    print(f"identity architecture: OK ({len(REQUIRED)} controls verified)")


if __name__ == "__main__":
    main()
