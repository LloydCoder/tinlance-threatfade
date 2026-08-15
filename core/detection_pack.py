"""Versioned detection-pack metadata and validation."""
from dataclasses import dataclass, asdict
from typing import Dict, List


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    version: str
    name: str
    description: str
    mitre: List[str]


DEFAULT_RULES = (
    DetectionRule("TF-C2-001", "1.0.0", "C2 signal fade", "Sustained reduction in observable C2 activity.", ["T1027"]),
    DetectionRule("TF-LOTL-001", "1.0.0", "LOTL gradual fade", "Gradual reduction in behavioral signal strength.", ["T1218"]),
    DetectionRule("TF-GNSS-001", "1.0.0", "GNSS interference", "Anomalous loss or disruption of navigation signals.", ["T1562"]),
)


def detection_pack() -> Dict[str, object]:
    return {
        "name": "ThreatFade Core Detection Pack",
        "version": "1.0.0",
        "rules": [asdict(rule) for rule in DEFAULT_RULES],
    }


def validate_pack(pack: Dict[str, object]) -> None:
    if not pack.get("name") or not pack.get("version"):
        raise ValueError("Detection pack requires name and version")
    rules = pack.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("Detection pack must contain rules")
    for rule in rules:
        for field in ("rule_id", "version", "name", "description", "mitre"):
            if field not in rule:
                raise ValueError(f"Rule missing required field: {field}")
