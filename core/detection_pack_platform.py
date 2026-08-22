"""Detection-pack manifest, compatibility, signing, and provenance primitives.

The module is intentionally dependency-light. Ed25519 is used for pack signatures;
provenance follows the in-toto Statement shape and uses the SLSA v1 predicate URI
without claiming SLSA conformance for the repository itself.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .detection_pack_registry import canonical_content, content_hash

SCHEMA_VERSION = "1.0.0"
SLSA_PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class PackManifest:
    schema_version: str
    pack_id: str
    version: str
    name: str
    description: str
    engine_api: str
    min_engine_version: str
    rules: tuple[Mapping[str, Any], ...]
    max_engine_version: str | None = None
    dependencies: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: str | None = None
    modified_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["rules"] = [dict(rule) for rule in self.rules]
        value["dependencies"] = list(self.dependencies)
        value["metadata"] = dict(self.metadata)
        return value


def _semver(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not SEMVER_RE.fullmatch(value):
        raise ValueError(f"invalid semantic version: {value!r}")
    main = value.split("-", 1)[0]
    return tuple(int(part) for part in main.split("."))  # type: ignore[return-value]


def semver_compatible(engine_version: str, minimum: str, maximum: str | None = None) -> bool:
    current = _semver(engine_version)
    lower = _semver(minimum)
    if current < lower:
        return False
    return maximum is None or current <= _semver(maximum)


def validate_manifest(manifest: Mapping[str, Any]) -> None:
    required = ("schema_version", "pack_id", "version", "name", "description", "engine_api", "min_engine_version", "rules")
    missing = [field for field in required if field not in manifest]
    if missing:
        raise ValueError(f"manifest missing required fields: {', '.join(missing)}")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported manifest schema: {manifest['schema_version']!r}")
    for field in ("pack_id", "version", "engine_api", "min_engine_version"):
        if not isinstance(manifest[field], str) or not manifest[field].strip():
            raise ValueError(f"manifest field {field!r} must be a non-empty string")
    _semver(manifest["version"])
    _semver(manifest["min_engine_version"])
    if manifest.get("max_engine_version") is not None:
        _semver(manifest["max_engine_version"])
    if not isinstance(manifest["rules"], Sequence) or isinstance(manifest["rules"], (str, bytes)) or not manifest["rules"]:
        raise ValueError("manifest rules must be a non-empty list")
    seen: set[str] = set()
    for rule in manifest["rules"]:
        if not isinstance(rule, Mapping):
            raise ValueError("each detection rule must be an object")
        for field in ("rule_id", "version", "name", "description", "mitre"):
            if field not in rule:
                raise ValueError(f"rule missing required field: {field}")
        rule_id = str(rule["rule_id"])
        if rule_id in seen:
            raise ValueError(f"duplicate rule_id: {rule_id}")
        seen.add(rule_id)
        _semver(str(rule["version"]))
        if not isinstance(rule["mitre"], Sequence) or isinstance(rule["mitre"], (str, bytes)):
            raise ValueError(f"rule {rule_id} mitre must be a list")
    if not semver_compatible(manifest["min_engine_version"], manifest["min_engine_version"], manifest.get("max_engine_version")):
        raise ValueError("invalid engine version range")


def canonical_manifest(manifest: Mapping[str, Any]) -> bytes:
    validate_manifest(manifest)
    return canonical_content(manifest)


def manifest_hash(manifest: Mapping[str, Any]) -> str:
    return content_hash(manifest)


def generate_signing_key() -> tuple[str, str]:
    """Return URL-safe base64 raw Ed25519 private/public keys."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    private_bytes = private.private_bytes_raw()
    public_bytes = public.public_bytes_raw()
    return (
        base64.urlsafe_b64encode(private_bytes).decode("ascii"),
        base64.urlsafe_b64encode(public_bytes).decode("ascii"),
    )


def sign_manifest(manifest: Mapping[str, Any], private_key_b64: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(private_key_b64.encode("ascii")))
    signature = key.sign(canonical_manifest(manifest))
    return base64.b64encode(signature).decode("ascii")


def verify_manifest_signature(manifest: Mapping[str, Any], signature_b64: str, public_key_b64: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(public_key_b64.encode("ascii")))
        key.verify(base64.b64decode(signature_b64.encode("ascii")), canonical_manifest(manifest))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def build_provenance(manifest: Mapping[str, Any], *, source_uri: str, source_revision: str, builder_id: str) -> dict[str, Any]:
    digest = manifest_hash(manifest)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": str(manifest["pack_id"]), "digest": {"sha256": digest}}],
        "predicateType": SLSA_PROVENANCE_PREDICATE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://threatfade.tinlance.com/detection-pack/v1",
                "externalParameters": {"sourceUri": source_uri, "sourceRevision": source_revision},
                "resolvedDependencies": [{"uri": source_uri, "digest": {"sha256": digest}}],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": f"pack-{digest[:16]}", "startedOn": datetime.now(timezone.utc).isoformat()},
            },
        },
    }
