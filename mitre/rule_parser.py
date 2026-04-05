"""
MITRE TTP Matcher
Maps detected patterns to MITRE ATT&CK framework.
"""

from typing import Dict, Any


def match_mitre_ttp(result: Dict[str, Any]) -> str:
    if not result.get("detected"):
        return "No match"

    score = result.get("score", 0.0)
    entropy = result.get("entropy", 0.0)
    drop_ratio = result.get("drop_ratio", 0.0)
    z_outlier = result.get("z_outlier", 0.0)
    confidence = result.get("confidence", "info")
    rules_matched = result.get("rules_matched", 0)

    if z_outlier >= 10:
        return "T1573.002 – Encrypted Channel: Asymmetric Cryptography"

    if z_outlier >= 5 and drop_ratio >= 0.4:
        return "T1071.001 – Application Layer Protocol: Web Protocols"

    if z_outlier >= 3 and confidence in ("high", "critical"):
        return "T1571 – Non-Standard Port"

    if drop_ratio >= 0.6 and rules_matched >= 1:
        return "T1205 – Traffic Signaling"

    if drop_ratio >= 0.5:
        return "T1071.004 – Application Layer Protocol: DNS"

    if score >= 0.3 and rules_matched >= 1:
        return "T1202 – Indirect Command Execution"

    if score >= 0.2:
        return "T1027 – Obfuscated Files or Information"

    return "T1027 – Obfuscated Files or Information"


def get_mitre_description(ttp: str) -> str:
    descriptions = {
        "T1573.002": "Encrypted C2 channel with high statistical anomaly in packet timing",
        "T1071.001": "C2 over standard web protocols with evasion timing patterns",
        "T1071.004": "DNS-based C2 with intermittent beaconing to avoid detection",
        "T1571": "C2 communication over non-standard ports with anomalous patterns",
        "T1205": "Traffic signaling used to trigger attacker actions on target",
        "T1202": "Using native OS commands to execute code covertly",
        "T1027": "Obfuscating command execution or payload delivery",
    }
    base_ttp = ttp.split(" – ")[0]
    return descriptions.get(base_ttp, "Unknown TTP")
