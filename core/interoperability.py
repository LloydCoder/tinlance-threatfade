"""Portable detection exports: Sigma and STIX 2.1 bundles."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def _stix_id(kind: str) -> str:
    return f"{kind}--{uuid.uuid4()}"


def to_sigma(result: Dict[str, Any], title: str = "ThreatFade signal fade") -> Dict[str, Any]:
    confidence = str(result.get("confidence", "info")).lower()
    return {
        "title": title,
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": "Detects sustained reduction in observable signal activity.",
        "logsource": {"product": "threatfade", "service": "detection"},
        "detection": {
            "selection": {"detected": True, "confidence": confidence},
            "condition": "selection",
        },
        "level": "high" if confidence in {"high", "critical"} else confidence,
        "tags": ["attack.T1027", "threatfade.fade"],
    }


def to_stix_bundle(result: Dict[str, Any], source_name: str = "ThreatFade") -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    identity_id = _stix_id("identity")
    traffic_id = _stix_id("network-traffic")
    observed_id = _stix_id("observed-data")
    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now,
                "modified": now,
                "name": source_name,
                "identity_class": "tool",
            },
            {
                "type": "network-traffic",
                "spec_version": "2.1",
                "id": traffic_id,
                "protocols": ["unknown"],
            },
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": observed_id,
                "created": now,
                "modified": now,
                "first_observed": now,
                "last_observed": now,
                "number_observed": 1,
                "object_refs": [traffic_id],
                "x_threatfade_score": float(result.get("score", 0.0)),
                "x_threatfade_confidence": str(result.get("confidence", "info")),
                "x_threatfade_fade_start": int(result.get("fade_start", -1)),
            },
        ],
    }


def export_interoperability(result: Dict[str, Any], output_dir: str = "reports/interoperability") -> Dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    sigma_path = out / "threatfade_detection.yml"
    stix_path = out / "threatfade_bundle.json"
    sigma_path.write_text(json.dumps(to_sigma(result), indent=2), encoding="utf-8")
    stix_path.write_text(json.dumps(to_stix_bundle(result), indent=2), encoding="utf-8")
    return {"sigma": str(sigma_path), "stix": str(stix_path)}
