#!/usr/bin/env python3
"""Validate the repository's Group 1 security-architecture artifacts.

This is intentionally deterministic: it checks that the architecture, threat
model, ASVS baseline, and build-status documents retain the required structure.
It does not claim that a document proves a control is implemented; executable
security tests and deployment evidence are required for that.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

REQUIRED_FILES = {
    "security_architecture": DOCS / "SECURITY_ARCHITECTURE.md",
    "threat_model": DOCS / "THREAT_MODEL.md",
    "asvs_matrix": DOCS / "ASVS_5.0_MATRIX.md",
}

REQUIRED_HEADINGS = {
    "security_architecture": [
        "# ThreatFade Security Architecture",
        "## 2. Security objectives",
        "## 3. Security zones and trust boundaries",
        "## 7. Security invariants",
        "## 10. High-risk design decisions",
    ],
    "threat_model": [
        "# ThreatFade Threat Model",
        "## 2. Assets",
        "## 3. Actors",
        "## 4. Trust boundaries",
        "## 6. STRIDE analysis",
        "## 7. Risk register",
        "## 8. Security invariants",
        "## 9. Abuse cases requiring continuous regression tests",
    ],
    "asvs_matrix": [
        "# ThreatFade OWASP ASVS 5.0 Verification Matrix",
        "## Chapter-level applicability matrix",
        "## High-priority requirement verification baseline",
        "## NIST CSF 2.0 alignment",
        "## Verification rules",
    ],
}


def fail(message: str) -> None:
    raise SystemExit(f"security architecture validation failed: {message}")


def find_unsupported_assurance_claims(text: str) -> list[str]:
    """Return lines containing affirmative unsupported certification claims.

    Security documentation must reject actual claims of certification while
    allowing explicit assurance-boundary language such as "not a claim of
    ASVS certification". The previous substring check treated that required
    disclaimer as a violation, causing CI to fail deterministically.
    """
    forbidden_phrases = (
        "asvs certified",
        "asvs certification",
        "soc 2 certified",
        "iso 27001 certified",
    )
    disclaimer_markers = (
        "not a certification claim",
        "not a claim of asvs certification",
        "does not represent soc 2",
        "does not represent iso 27001",
        "does not claim",
        "without certification",
    )

    findings: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip().lower()
        if not line or not any(phrase in line for phrase in forbidden_phrases):
            continue
        if any(marker in line for marker in disclaimer_markers):
            continue
        findings.append(raw_line.strip())
    return findings


def main() -> None:
    contents = {}
    for name, path in REQUIRED_FILES.items():
        if not path.is_file():
            fail(f"missing {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            fail(f"empty {path.relative_to(ROOT)}")
        contents[name] = text
        for heading in REQUIRED_HEADINGS[name]:
            if heading not in text:
                fail(f"{path.relative_to(ROOT)} missing heading: {heading}")

    matrix = contents["asvs_matrix"]
    for chapter in range(1, 18):
        if f"| V{chapter} |" not in matrix:
            fail(f"ASVS matrix missing V{chapter} chapter")

    threat_model = contents["threat_model"]
    for token in ("R-01", "R-12", "TB-01", "TB-10", "SI-01", "SI-10"):
        if token not in threat_model:
            fail(f"threat model missing required control marker {token}")

    architecture = contents["security_architecture"]
    for token in ("TB-01", "TB-09", "SI-01", "SI-10"):
        if token not in architecture:
            fail(f"security architecture missing required marker {token}")

    for name, text in contents.items():
        findings = find_unsupported_assurance_claims(text)
        if findings:
            fail(
                "documentation must not make unsupported assurance claim "
                f"in {name}: {findings[0]}"
            )

    print("security architecture: OK")
    print("threat model: OK")
    print("ASVS 5.0 matrix: OK (17 chapters present)")
    print("unsupported certification claims: none")


if __name__ == "__main__":
    main()
