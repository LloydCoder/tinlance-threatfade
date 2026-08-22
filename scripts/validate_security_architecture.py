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

    combined = "\n".join(contents.values()).lower()
    forbidden_claims = (
        "asvs certified",
        "asvs certification",
        "soc 2 certified",
        "iso 27001 certified",
    )
    for phrase in forbidden_claims:
        if phrase in combined:
            fail(f"documentation must not make unsupported assurance claim: {phrase}")

    print("security architecture: OK")
    print("threat model: OK")
    print("ASVS 5.0 matrix: OK (17 chapters present)")
    print("unsupported certification claims: none")


if __name__ == "__main__":
    main()
