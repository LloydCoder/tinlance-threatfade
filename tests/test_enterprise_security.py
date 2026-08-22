import os

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

from core.enterprise import ALLOWED_JWT_ALGORITHMS, OIDCValidator, Principal, authenticate, authorize, require_tenant


def _request(headers=None):
    class Client:
        host = "127.0.0.1"

    class Request:
        def __init__(self):
            self.headers = headers or {}
            self.client = Client()

    return Request()


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


def test_api_key_is_not_an_production_authentication_path(monkeypatch):
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


def test_oidc_validator_rejects_invalid_role_claim(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key())
    validator = OIDCValidator()
    validator.issuer = "https://issuer.example"
    validator.audience = "threatfade"
    validator.jwks_url = "https://issuer.example/keys"
    validator._jwks = {"keys": [{**__import__("json").loads(public_jwk), "kid": "k1", "alg": "RS256", "use": "sig"}]}
    validator._jwks_at = __import__("time").monotonic()
    token = jwt.encode(
        {
            "iss": validator.issuer,
            "aud": validator.audience,
            "sub": "user-1",
            "tenant_id": "tenant-a",
            "roles": "admin",
            "iat": __import__("time").time(),
            "exp": __import__("time").time() + 300,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    with pytest.raises(HTTPException) as exc:
        validator.validate(token)
    assert exc.value.status_code == 403


def test_oidc_validator_accepts_namespaced_roles_and_tenant():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    import json
    import time

    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    validator = OIDCValidator()
    validator.issuer = "https://issuer.example"
    validator.audience = "threatfade"
    validator.jwks_url = "https://issuer.example/keys"
    validator._jwks = {"keys": [{**public, "kid": "k1", "alg": "RS256", "use": "sig"}]}
    validator._jwks_at = time.monotonic()
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
    import json
    import time

    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    validator = OIDCValidator()
    validator.issuer = "https://issuer.example"
    validator.audience = "threatfade"
    validator.jwks_url = "https://issuer.example/keys"
    validator._jwks = {"keys": [{**public, "kid": "different", "alg": "RS256", "use": "sig"}]}
    validator._jwks_at = time.monotonic()
    monkeypatch.setattr(validator, "_load_jwks", lambda: validator._jwks)
    token = jwt.encode(
        {"iss": validator.issuer, "aud": validator.audience, "sub": "u", "tenant_id": "t", "iat": int(time.time()), "exp": int(time.time()) + 60},
        private_key,
        algorithm="RS256",
        headers={"kid": "missing"},
    )
    with pytest.raises(HTTPException) as exc:
        validator.validate(token)
    assert exc.value.status_code == 401
