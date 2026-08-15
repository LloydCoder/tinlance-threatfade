"""Human-readable evidence generation for ThreatFade detections."""
from typing import Any, Dict, List


def build_evidence(result: Dict[str, Any]) -> Dict[str, Any]:
    """Return structured evidence without changing the detector's score."""
    evidence: List[str] = []
    if result.get("drop_ratio", 0) >= 0.5:
        evidence.append("sustained reduction in signal activity")
    if result.get("z_outlier", 0) >= 3:
        evidence.append("statistically significant deviation from baseline")
    if result.get("rules_matched", 0) >= 1:
        evidence.append(f"{result['rules_matched']} heuristic detection rule(s) matched")
    if result.get("ml_anomaly"):
        evidence.append("ML anomaly detector flagged the signal")
    if not evidence:
        evidence.append("no strong fade evidence")

    return {
        "summary": "; ".join(evidence),
        "signals": evidence,
        "metrics": {
            "score": round(float(result.get("score", 0.0)), 6),
            "entropy": round(float(result.get("entropy", 0.0)), 6),
            "drop_ratio": round(float(result.get("drop_ratio", 0.0)), 6),
            "z_outlier": round(float(result.get("z_outlier", 0.0)), 6),
            "rules_matched": int(result.get("rules_matched", 0)),
        },
        "fade_start": int(result.get("fade_start", -1)),
    }
