"""Enterprise identity, RBAC and tenant isolation tests."""
import os
import pytest
from fastapi import HTTPException
from core.enterprise import Principal, authorize, require_tenant, ROLE_PERMISSIONS


def test_role_matrix_is_explicit():
    assert ROLE_PERMISSIONS["viewer"] == {"detection:read", "case:read"}
    assert "detection:run" in ROLE_PERMISSIONS["analyst"]
    assert "*" in ROLE_PERMISSIONS["admin"]


def test_viewer_cannot_run_detection():
    with pytest.raises(HTTPException) as exc:
        authorize(Principal("u", "tenant-a", {"viewer"}), "detection:run")
    assert exc.value.status_code == 403


def test_analyst_can_run_detection():
    authorize(Principal("u", "tenant-a", {"analyst"}), "detection:run")


def test_cross_tenant_isolation():
    with pytest.raises(HTTPException) as exc:
        require_tenant(Principal("u", "tenant-a", {"analyst"}), "tenant-b")
    assert exc.value.status_code == 403


def test_tenant_admin_can_access_own_and_managed_tenant():
    assert require_tenant(Principal("u", "tenant-a", {"tenant_admin"}), "tenant-b") == "tenant-b"
