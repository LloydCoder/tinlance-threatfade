"""
ThreatFade MITRE ATT&CK Rule Parser
Maps detection results to specific ATT&CK sub-techniques.
Based on real ATT&CK v14 taxonomy.
"""

from typing import Dict, Any, List, Tuple


# Full ATT&CK sub-technique database relevant to fade/evasion detection
ATTACK_DB = {
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries use HTTP/HTTPS for C2 with evasion timing to blend with normal traffic.",
        "detection": "Monitor for unusual HTTP/HTTPS traffic patterns with periodic quiet windows.",
        "severity": "high",
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "description": "DNS used as C2 channel with intermittent beaconing to avoid detection.",
        "detection": "Monitor DNS query frequency and timing anomalies.",
        "severity": "high",
    },
    "T1573.001": {
        "name": "Encrypted Channel: Symmetric Cryptography",
        "tactic": "Command and Control",
        "description": "C2 traffic encrypted with symmetric keys, causing high entropy in payloads.",
        "detection": "Monitor for high-entropy encrypted traffic with periodic gaps.",
        "severity": "high",
    },
    "T1573.002": {
        "name": "Encrypted Channel: Asymmetric Cryptography",
        "tactic": "Command and Control",
        "description": "Asymmetric encryption used for C2 with very high statistical anomaly.",
        "detection": "Monitor for asymmetrically encrypted beacon traffic with z-score outliers.",
        "severity": "critical",
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": "C2 over non-standard ports with anomalous packet timing.",
        "detection": "Monitor for unexpected ports with periodic traffic patterns.",
        "severity": "medium",
    },
    "T1205.001": {
        "name": "Traffic Signaling: Port Knocking",
        "tactic": "Defense Evasion",
        "description": "Sequential port knocks used to signal C2 availability while appearing inactive.",
        "detection": "Monitor for sequential connection attempts followed by silence.",
        "severity": "high",
    },
    "T1027.001": {
        "name": "Obfuscated Files or Information: Binary Padding",
        "tactic": "Defense Evasion",
        "description": "Binary padding used to obfuscate payloads and alter entropy signatures.",
        "detection": "Monitor for binary files with unusual padding patterns.",
        "severity": "medium",
    },
    "T1027.003": {
        "name": "Obfuscated Files or Information: Steganography",
        "tactic": "Defense Evasion",
        "description": "Data hidden in legitimate-looking traffic using steganographic techniques.",
        "detection": "Monitor for anomalous entropy in seemingly normal traffic.",
        "severity": "high",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries obfuscate command execution or payload delivery.",
        "detection": "Monitor for obfuscated scripts, encoded commands, or unusual data encoding.",
        "severity": "medium",
    },
    "T1202": {
        "name": "Indirect Command Execution",
        "tactic": "Defense Evasion",
        "description": "Native OS utilities used to execute commands indirectly.",
        "detection": "Monitor for LOLBins executing unusual commands.",
        "severity": "medium",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Data exfiltrated over non-standard protocols with evasion timing.",
        "detection": "Monitor for unusual protocol usage with periodic bursts.",
        "severity": "high",
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Raw network protocols (ICMP, UDP) used for C2 with fade patterns.",
        "detection": "Monitor for unusual ICMP/UDP patterns with intermittent activity.",
        "severity": "medium",
    },
}


def _score_to_severity(score: float, z_outlier: float, confidence: str) -> str:
    if z_outlier >= 10 or confidence == "critical":
        return "critical"
    elif score >= 0.4 or z_outlier >= 5 or confidence == "high":
        return "high"
    elif score >= 0.25 or z_outlier >= 3 or confidence == "medium":
        return "medium"
    return "low"


def match_mitre_ttp(result: Dict[str, Any]) -> str:
    """Primary TTP match — returns most specific sub-technique."""
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
    if drop_ratio >= 0.6 and rules_matched >= 2:
        return "T1205.001 – Traffic Signaling: Port Knocking"
    if drop_ratio >= 0.6 and rules_matched >= 1:
        return "T1071.004 – Application Layer Protocol: DNS"
    if entropy >= 6.5:
        return "T1573.001 – Encrypted Channel: Symmetric Cryptography"
    if drop_ratio >= 0.5:
        return "T1027.003 – Obfuscated Files: Steganography"
    if score >= 0.3 and rules_matched >= 1:
        return "T1202 – Indirect Command Execution"
    if score >= 0.2:
        return "T1027 – Obfuscated Files or Information"
    return "T1027 – Obfuscated Files or Information"


def match_all_ttps(result: Dict[str, Any]) -> List[Dict[str, str]]:
    """Returns all matching TTPs ranked by relevance."""
    if not result.get("detected"):
        return []

    score = result.get("score", 0.0)
    z_outlier = result.get("z_outlier", 0.0)
    drop_ratio = result.get("drop_ratio", 0.0)
    confidence = result.get("confidence", "info")
    rules_matched = result.get("rules_matched", 0)

    matches = []

    if z_outlier >= 10:
        matches.append(("T1573.002", 1.0))
    if z_outlier >= 5:
        matches.append(("T1573.001", 0.8))
    if z_outlier >= 3:
        matches.append(("T1571", 0.7))
    if drop_ratio >= 0.6:
        matches.append(("T1071.004", 0.75))
        matches.append(("T1205.001", 0.65))
    if drop_ratio >= 0.4:
        matches.append(("T1071.001", 0.6))
    if score >= 0.3:
        matches.append(("T1027", 0.5))
        matches.append(("T1202", 0.45))

    results = []
    seen = set()
    for ttp_id, relevance in sorted(matches, key=lambda x: -x[1]):
        if ttp_id not in seen and ttp_id in ATTACK_DB:
            seen.add(ttp_id)
            info = ATTACK_DB[ttp_id]
            results.append({
                "ttp_id": ttp_id,
                "name": info["name"],
                "tactic": info["tactic"],
                "description": info["description"],
                "detection": info["detection"],
                "severity": info["severity"],
                "relevance": round(relevance, 2),
            })
    return results


def get_mitre_description(ttp: str) -> str:
    base = ttp.split(" – ")[0].strip()
    if base in ATTACK_DB:
        return ATTACK_DB[base]["description"]
    return "Unknown TTP"


def get_mitre_detection_note(ttp: str) -> str:
    base = ttp.split(" – ")[0].strip()
    if base in ATTACK_DB:
        return ATTACK_DB[base]["detection"]
    return "No detection note available"


def get_mitre_tactic(ttp: str) -> str:
    base = ttp.split(" – ")[0].strip()
    if base in ATTACK_DB:
        return ATTACK_DB[base]["tactic"]
    return "Unknown"
