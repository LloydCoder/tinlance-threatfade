"""Fail-closed validation for the Phase 20 assurance package."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "docs" / "evaluation"

REQUIRED_FILES = (
    "INDEPENDENT_VALIDATION_PACKAGE.md",
    "PHASE_20_ASSURANCE_MANIFEST.json",
    "PENTEST_SCOPE.md",
    "PURPLE_TEAM_PROTOCOL.md",
    "SCALE_BENCHMARK_PROTOCOL.md",
)

REQUIRED_STATUSES = {
    "implemented",
    "internally-validated",
    "not-validated",
    "not-claimed",
}

FORBIDDEN_COMPLETION_PHRASES = (
    "independently validated",
    "independently audited",
    "independent penetration test completed",
    "certified",
)


def main() -> int:
    missing = [name for name in REQUIRED_FILES if not (EVAL / name).is_file()]
    if missing:
        raise SystemExit(f"missing Phase 20 evidence files: {', '.join(missing)}")

    manifest = json.loads((EVAL / "PHASE_20_ASSURANCE_MANIFEST.json").read_text())
    if manifest.get("status") != "preparation-ready":
        raise SystemExit("Phase 20 manifest must remain preparation-ready until external evidence exists")
    if manifest.get("external_validation") != "not_completed":
        raise SystemExit("external validation cannot be marked completed by repository preparation")
    if manifest.get("certification") != "not_claimed":
        raise SystemExit("certification must remain not-claimed without formal evidence")

    for claim in manifest.get("claims", []):
        if claim.get("status") not in REQUIRED_STATUSES:
            raise SystemExit(f"unsupported claim status: {claim.get('status')!r}")
        if claim.get("status") in {"not-validated", "not-claimed"} and claim.get("evidence"):
            raise SystemExit(f"unvalidated claim unexpectedly contains evidence: {claim.get('claim')}")

    package_text = (EVAL / "INDEPENDENT_VALIDATION_PACKAGE.md").read_text().lower()
    for phrase in FORBIDDEN_COMPLETION_PHRASES:
        if phrase in package_text and "not independently validated" not in package_text:
            raise SystemExit(f"assurance package contains an unqualified completion phrase: {phrase}")

    required_sections = (
        "## Assurance boundary",
        "## Required evaluator inputs",
        "## Required evaluator outputs",
        "## Independence requirements",
        "## Evidence chain",
        "## Publication gate",
    )
    for section in required_sections:
        if section.lower() not in package_text:
            raise SystemExit(f"missing required section: {section}")

    print("Phase 20 assurance preparation gate: GREEN")
    print("External validation: NOT COMPLETED")
    print("Certification: NOT CLAIMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
