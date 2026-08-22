import pytest

from core.detection_pack import detection_pack
from core.detection_pack_platform import (
    SCHEMA_VERSION,
    build_provenance,
    generate_signing_key,
    manifest_hash,
    semver_compatible,
    sign_manifest,
    validate_manifest,
    verify_manifest_signature,
)
from core.detection_pack_registry import make_identity, rollback


def manifest():
    base = detection_pack()
    return {
        "schema_version": SCHEMA_VERSION,
        "pack_id": "threatfade-core",
        "version": "1.0.0",
        "name": base["name"],
        "description": "ThreatFade core detection pack.",
        "engine_api": "1.0",
        "min_engine_version": "0.4.0",
        "rules": base["rules"],
        "dependencies": [],
        "metadata": {"license": "Apache-2.0"},
    }


def test_manifest_schema_and_semver_contract():
    value = manifest()
    validate_manifest(value)
    assert semver_compatible("0.5.0", "0.4.0", "0.6.0")
    assert not semver_compatible("0.3.9", "0.4.0")
    with pytest.raises(ValueError):
        validate_manifest({**value, "rules": [{"rule_id": "x"}]})


def test_ed25519_sign_and_tamper_detection():
    value = manifest()
    private, public = generate_signing_key()
    signature = sign_manifest(value, private)
    assert verify_manifest_signature(value, signature, public)
    changed = {**value, "description": "tampered"}
    assert not verify_manifest_signature(changed, signature, public)
    assert len(manifest_hash(value)) == 64


def test_provenance_subject_matches_manifest_digest():
    value = manifest()
    provenance = build_provenance(value, source_uri="https://github.com/LloydCoder/tinlance-threatfade", source_revision="main", builder_id="github-actions://ThreatFade")
    assert provenance["predicateType"] == "https://slsa.dev/provenance/v1"
    assert provenance["subject"][0]["digest"]["sha256"] == manifest_hash(value)


def test_rollback_only_targets_immutable_prior_pack():
    value = manifest()
    old = make_identity(value, "threatfade-core", "1.0.0", "validated")
    new = make_identity({**value, "version": "1.1.0"}, "threatfade-core", "1.1.0", "production")
    result = rollback(new, old)
    assert result.version == "1.0.0"
    assert result.lifecycle == "production"
    with pytest.raises(ValueError):
        rollback(new, new)
