import pytest

from core.detection_pack import detection_pack
from core.detection_pack_registry import content_hash, make_identity, transition, verify_identity


def test_identity_is_stable_and_detects_tampering():
    pack = detection_pack()
    identity = make_identity(pack, "threatfade-core", "1.0.0")
    assert verify_identity(pack, identity)
    changed = dict(pack)
    changed["version"] = "1.0.1"
    assert not verify_identity(changed, identity)
    assert len(identity.content_sha256) == 64


def test_lifecycle_requires_ordered_promotion():
    identity = make_identity(detection_pack(), "threatfade-core", "1.0.0")
    identity = transition(identity, "validated")
    identity = transition(identity, "canary")
    identity = transition(identity, "production")
    identity = transition(identity, "deprecated")
    assert identity.lifecycle == "deprecated"
    with pytest.raises(ValueError, match="invalid lifecycle"):
        transition(identity, "production")


def test_canonical_hash_is_order_stable():
    assert content_hash({"b": 2, "a": 1}) == content_hash({"a": 1, "b": 2})
