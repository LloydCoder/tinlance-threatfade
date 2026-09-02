import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from core.enterprise import (
    ALLOWED_JWT_ALGORITHMS,
    OIDCValidator,
    Principal,
    authenticate,
    authorize,
    require_tenant,
)


def _request(headers=None):
    class Client:
        host = "127.0.0.1"

    class Request:
        def __init__(self):
            self.headers = headers or {}
            self.client = Client()

    return Request()


def _validator(private_key, *, roles=None, tenant="tenant-a"):
    validator = OIDCValidator()
    validator.issuer = "https://issuer.example"
    validator.audience = "threatfade"
    validator.jwks_url = "https://issuer.example/keys"
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    validator._jwks = {"keys": [{**public, "kid": "k1", "alg": "RS256", "use": "sig"}]}
    validator._jwks_at = time.monotonic()
    claims = {
        "iss": validator.issuer,
        "aud": validator.audience,
        "sub": "user-1",
        "tenant_id": tenant,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    if roles is not None:
        claims["roles"] = roles
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "k1"})
    return validator, token


def test_role_permissions_are_explicit_and_tenant_scoped():
    analyst = Principal("u1", "tenant-a", {"analyst"})
    assert analyst.can("detection:run")
    assert analyst.can("case:write")
    assert not analyst.can("tenant:admin")
    with pytest.raises(HTTPException) as exc:
        require_tenant(analyst, "tenant-b")
    assert exc.value.status_code == 403


def test_global_admin_requires_explicit_claim():
    ordinary_admin = Principal("u1", "tenant-a", {"admin"})
    with pytest.raises(HTTPException):
        require_tenant(ordinary_admin, "tenant-b")
    global_admin = Principal("u2", "tenant-a", {"admin"}, claims={"global_admin": True})
    assert require_tenant(global_admin, "tenant-b") == "tenant-b"


def test_invalid_tenant_identifier_is_rejected():
    principal = Principal("u1", "tenant-a", {"analyst"})
    with pytest.raises(HTTPException) as exc:
        require_tenant(principal, "../tenant-b")
    assert exc.value.status_code == 400


def test_authorization_rejects_missing_permission():
    viewer = Principal("u1", "tenant-a", {"viewer"})
    with pytest.raises(HTTPException) as exc:
        authorize(viewer, "case:write")
    assert exc.value.status_code == 403


def test_production_never_accepts_development_auth(monkeypatch):
    monkeypatch.setenv("THREATFADE_ENV", "production")
    monkeypatch.setenv("THREATFADE_ALLOW_DEV_AUTH", "true")
    with pytest.raises(HTTPException) as exc:
        authenticate(_request({"X-Tenant-ID": "tenant-a"}))
    assert exc.value.status_code == 401


def test_api_key_is_not_a_production_authentication_path(monkeypatch):
    monkeypatch.setenv("THREATFADE_ENV", "production")
    monkeypatch.setenv("THREATFADE_API_KEY", "secret")
    with pytest.raises(HTTPException) as exc:
        authenticate(_request({"X-Tenant-ID": "tenant-a"}), "secret")
    assert exc.value.status_code == 401


def test_authorization_scheme_must_be_bearer(monkeypatch):
    monkeypatch.setenv("THREATFADE_ENV", "production")
    with pytest.raises(HTTPException) as exc:
        authenticate(_request({"Authorization": "Basic abc"}))
    assert exc.value.status_code == 401


def test_jwt_algorithm_allowlist_is_asymmetric_only():
    assert ALLOWED_JWT_ALGORITHMS == {"RS256", "RS384", "RS512"}
    assert "HS256" not in ALLOWED_JWT_ALGORITHMS
    assert "none" not in ALLOWED_JWT_ALGORITHMS


def test_oidc_validator_rejects_invalid_role_claim():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    validator, token = _validator(private_key, roles="admin")
    with pytest.raises(HTTPException) as exc:
        validator.validate(token)
    assert exc.value.status_code == 403


def test_oidc_validator_accepts_namespaced_roles_and_tenant():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    validator, _ = _validator(private_key)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    validator._jwks = {"keys": [{**public, "kid": "k1", "alg": "RS256", "use": "sig"}]}
    token = jwt.encode(
        {
            "iss": validator.issuer,
            "aud": validator.audience,
            "sub": "user-1",
            "https://tinlance.com/tenant_id": "tenant-a",
            "https://tinlance.com/roles": ["analyst"],
            "scope": "detection:read",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    principal = validator.validate(token)
    assert principal.subject == "user-1"
    assert principal.tenant_id == "tenant-a"
    assert principal.roles == {"analyst"}
    assert principal.can("detection:run")


def test_oidc_validator_rejects_unknown_key(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    validator, _ = _validator(private_key)
    unknown_keys = validator._jwks
    monkeypatch.setattr(validator, "_load_jwks", lambda: unknown_keys)
    token = jwt.encode(
        {
            "iss": validator.issuer,
            "aud": validator.audience,
            "sub": "u",
            "tenant_id": "t",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "missing"},
    )
    with pytest.raises(HTTPException) as exc:
        validator.validate(token)
    assert exc.value.status_code == 401


def test_oidc_validator_rejects_hs256_token():
    validator = OIDCValidator()
    validator.issuer = "https://issuer.example"
    validator.audience = "threatfade"
    validator.jwks_url = "https://issuer.example/keys"
    token = jwt.encode(
        {
            "iss": validator.issuer,
            "aud": validator.audience,
            "sub": "u",
            "tenant_id": "t",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        },
        "shared-secret",
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc:
        validator.validate(token)
    assert exc.value.status_code == 401


def test_tenant_session_reapplies_rls_context_after_commit():
    from sqlalchemy import select, text

    from core.storage import CaseRecord, tenant_session

    tenant_a = "tenant-rls-a"
    tenant_b = "tenant-rls-b"

    # Seed one row for each tenant through their own tenant-bound sessions.
    with tenant_session(tenant_a) as session:
        session.add(
            CaseRecord(
                tenant_id=tenant_a,
                owner="user-a",
                title="Tenant A case",
                status="open",
            )
        )
        session.commit()

    with tenant_session(tenant_b) as session:
        session.add(
            CaseRecord(
                tenant_id=tenant_b,
                owner="user-b",
                title="Tenant B case",
                status="open",
            )
        )
        session.commit()

    # Verify that the tenant context is established automatically and is
    # re-established when SQLAlchemy starts a new transaction after commit.
    with tenant_session(tenant_a) as session:
        first_context = session.scalar(
            text("SELECT current_setting('threatfade.tenant_id', true)")
        )
        assert first_context == tenant_a

        visible_first = list(
            session.scalars(
                select(CaseRecord).order_by(CaseRecord.id)
            )
        )
        assert [row.tenant_id for row in visible_first] == [tenant_a]

        session.commit()

        second_context = session.scalar(
            text("SELECT current_setting('threatfade.tenant_id', true)")
        )
        assert second_context == tenant_a

        visible_second = list(
            session.scalars(
                select(CaseRecord).order_by(CaseRecord.id)
            )
        )
        assert [row.tenant_id for row in visible_second] == [tenant_a]

        # Even an explicitly guessed cross-tenant identifier must remain
        # invisible because PostgreSQL RLS is the enforcement boundary.
        guessed = session.scalar(
            select(CaseRecord).where(CaseRecord.tenant_id == tenant_b)
        )
        assert guessed is None


def test_oidc_authentication_rejects_disabled_local_account(monkeypatch):
    from types import SimpleNamespace

    principal = Principal(
        "disabled-user",
        "tenant-a",
        {"analyst"},
        claims={"email": "disabled@example.test"},
    )

    monkeypatch.setattr(
        "core.enterprise.OIDC.validate",
        lambda token: principal,
    )
    monkeypatch.setattr(
        "core.identity.ensure_user",
        lambda subject, email=None, name=None: SimpleNamespace(
            subject=subject,
            disabled=1,
        ),
    )

    with pytest.raises(HTTPException) as exc:
        authenticate(
            _request(
                {
                    "Authorization": "Bearer valid-oidc-token",
                }
            )
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "Authentication account is disabled"


def test_oidc_authentication_accepts_active_local_account(monkeypatch):
    from types import SimpleNamespace

    principal = Principal(
        "active-user",
        "tenant-a",
        {"analyst"},
        claims={"email": "active@example.test"},
    )

    monkeypatch.setattr(
        "core.enterprise.OIDC.validate",
        lambda token: principal,
    )
    monkeypatch.setattr(
        "core.identity.ensure_user",
        lambda subject, email=None, name=None: SimpleNamespace(
            subject=subject,
            disabled=0,
        ),
    )

    result = authenticate(
        _request(
            {
                "Authorization": "Bearer valid-oidc-token",
            }
        )
    )

    assert result is principal
