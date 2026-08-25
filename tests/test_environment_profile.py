import pytest
from datetime import datetime, timezone
from core.environment_profile import EnvironmentProfile, ProfileStore, SensitivityThresholds, ObservationContext, assess_authorization, validate_profile

def profile(tenant="tenant-a", version=1, status="draft", created_at=None):
    return EnvironmentProfile(profile_id="office", tenant_id=tenant, version=version, name="Office baseline", expected_protocols=("https", "dns"), expected_ports=(53, 443), baseline_entropy={"https": 2.4}, baseline_periodicity={"https": 0.7}, expected_destinations=("updates.example",), sensitivity=SensitivityThresholds(entropy_zscore=3.5), allowed_integrations=("fusionops",), deployment_constraints={"region": "eu"}, status=status, created_by="admin", created_at=created_at or datetime.now(timezone.utc))

def test_profile_is_deterministically_valid_and_hashed():
    p=profile(); validate_profile(p); assert p.digest()==p.digest()

def test_versions_are_immutable_and_monotonic():
    s=ProfileStore(); s.put(profile(version=1),actor_tenant="tenant-a"); s.put(profile(version=2),actor_tenant="tenant-a")
    with pytest.raises(ValueError): s.put(profile(version=2),actor_tenant="tenant-a")
    with pytest.raises(ValueError): s.put(profile(version=4),actor_tenant="tenant-a")

def test_active_profile_conflict_requires_explicit_activation():
    s=ProfileStore(); s.put(profile(version=1,status="active"),actor_tenant="tenant-a")
    with pytest.raises(ValueError): s.put(profile(version=2,status="active"),actor_tenant="tenant-a")
    s.put(profile(version=2),actor_tenant="tenant-a"); s.activate("tenant-a","office",2,actor_tenant="tenant-a"); assert s.active("tenant-a","office",actor_tenant="tenant-a").version==2

def test_rollback_is_audited_and_changes_active_version():
    s=ProfileStore(); s.put(profile(version=1,status="active"),actor_tenant="tenant-a"); s.put(profile(version=2),actor_tenant="tenant-a"); s.activate("tenant-a","office",2,actor_tenant="tenant-a"); s.rollback("tenant-a","office",1,actor_tenant="tenant-a")
    assert s.active("tenant-a","office",actor_tenant="tenant-a").version==1; assert s.audit("tenant-a",actor_tenant="tenant-a")[-1]["action"]=="rollback"

def test_tenant_crossover_is_denied():
    s=ProfileStore()
    with pytest.raises(PermissionError): s.put(profile(),actor_tenant="tenant-b")
    s.put(profile(),actor_tenant="tenant-a")
    with pytest.raises(PermissionError): s.active("tenant-a","office",actor_tenant="tenant-b")
    with pytest.raises(PermissionError): s.rollback("tenant-a","office",1,actor_tenant="tenant-b")

def test_malformed_profile_is_rejected():
    with pytest.raises(ValueError): EnvironmentProfile(profile_id="x",tenant_id="t",version=0,name="bad")
    with pytest.raises(ValueError): EnvironmentProfile(profile_id="x",tenant_id="t",version=1,name="bad",expected_ports=(70000,))
    with pytest.raises(ValueError): SensitivityThresholds(periodicity_score=2)
    with pytest.raises(ValueError): EnvironmentProfile(profile_id="x",tenant_id="t",version=1,name="bad",schema_version="0.1")

def test_observed_behavior_is_separate_from_authorization():
    a=assess_authorization(profile(),ObservationContext(protocol="https",port=443,destination="unknown.example")); assert not a.authorized; assert a.deviations==("destination",); assert a.evidence_required

def test_observation_within_profile_has_no_deviation():
    a=assess_authorization(profile(),ObservationContext(protocol="https",port=443,destination="updates.example",entropy=2.5,periodicity=0.75)); assert a.authorized; assert a.deviations==()

def test_duplicate_profile_values_are_rejected():
    with pytest.raises(ValueError): validate_profile(EnvironmentProfile(profile_id="x",tenant_id="t",version=1,name="bad",expected_ports=(443,443)))
