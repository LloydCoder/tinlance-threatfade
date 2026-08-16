"""Evidence-first explanations for ThreatFade detections and non-detections."""
from typing import Any, Dict, List


def build_evidence(result: Dict[str, Any]) -> Dict[str, Any]:
    """Return structured, analyst-readable evidence without changing detector scores."""
    signals: List[str] = []
    contributions: List[Dict[str, Any]] = []
    drop_ratio = float(result.get("drop_ratio", 0.0))
    z_outlier = float(result.get("z_outlier", 0.0))
    rules = int(result.get("rules_matched", 0))
    ml_anomaly = bool(result.get("ml_anomaly", False))

    if drop_ratio >= 0.5:
        signals.append("sustained reduction in signal activity")
        contributions.append({"factor": "drop_ratio", "value": round(drop_ratio, 6), "threshold": 0.5, "impact": "supporting"})
    else:
        contributions.append({"factor": "drop_ratio", "value": round(drop_ratio, 6), "threshold": 0.5, "impact": "below_threshold"})
    if z_outlier >= 3:
        signals.append("statistically significant deviation from baseline")
        contributions.append({"factor": "z_outlier", "value": round(z_outlier, 6), "threshold": 3.0, "impact": "supporting"})
    else:
        contributions.append({"factor": "z_outlier", "value": round(z_outlier, 6), "threshold": 3.0, "impact": "below_threshold"})
    if rules >= 1:
        signals.append(f"{rules} heuristic detection rule(s) matched")
        contributions.append({"factor": "rules_matched", "value": rules, "threshold": 1, "impact": "supporting"})
    if ml_anomaly:
        signals.append("ML anomaly detector flagged the signal")
        contributions.append({"factor": "ml_anomaly", "value": True, "impact": "supporting"})

    detected = bool(result.get("detected", False))
    if not signals:
        signals.append("no strong fade evidence")

    return {
        "decision": "detected" if detected else "not_detected",
        "summary": "; ".join(signals),
        "signals": signals,
        "contributions": contributions,
        "metrics": {
            "score": round(float(result.get("score", 0.0)), 6),
            "entropy": round(float(result.get("entropy", 0.0)), 6),
            "drop_ratio": round(drop_ratio, 6),
            "z_outlier": round(z_outlier, 6),
            "rules_matched": rules,
        },
        "fade_start": int(result.get("fade_start", -1)),
        "limitations": ["This explanation describes detector evidence; it is not proof of malicious intent."],
    }
