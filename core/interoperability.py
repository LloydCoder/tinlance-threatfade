"""Portable detection exports: Sigma and STIX 2.1-compatible bundles."""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def to_sigma(result: Dict[str, Any], title: str = "ThreatFade signal fade") -> Dict[str, Any]:
    confidence = str(result.get("confidence", "info")).lower()
    return {
        "title": title,
        "id": "threatfade-signal-fade",
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
    confidence = str(result.get("confidence", "info"))
    observed = {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--threatfade-detection",
        "created": now,
        "modified": now,
        "first_observed": now,
        "last_observed": now,
        "number_observed": 1,
        "object_refs": [],
        "x_threatfade_score": float(result.get("score", 0.0)),
        "x_threatfade_confidence": confidence,
        "x_threatfade_fade_start": int(result.get("fade_start", -1)),
    }
    return {
        "type": "bundle",
        "id": "bundle--threatfade-detection",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--threatfade",
                "created": now,
                "modified": now,
                "name": source_name,
                "identity_class": "tool",
            },
            observed,
        ],
    }


def export_interoperability(result: Dict[str, Any], output_dir: str = "reports/interoperability") -> Dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    sigma_path = out / "threatfade_detection.yml"
    stix_path = out / "threatfade_bundle.json"
    # JSON is valid YAML 1.2, so this remains dependency-free.
    sigma_path.write_text(json.dumps(to_sigma(result), indent=2), encoding="utf-8")
    stix_path.write_text(json.dumps(to_stix_bundle(result), indent=2), encoding="utf-8")
    return {"sigma": str(sigma_path), "stix": str(stix_path)}
