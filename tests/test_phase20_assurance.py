from pathlib import Path
import json

from scripts.validate_phase20_assurance import EVAL, REQUIRED_FILES


def test_phase20_assurance_manifest_is_preparation_only():
    manifest = json.loads((EVAL / "PHASE_20_ASSURANCE_MANIFEST.json").read_text())
    assert manifest["status"] == "preparation-ready"
    assert manifest["external_validation"] == "not_completed"
    assert manifest["certification"] == "not_claimed"


def test_phase20_required_evidence_package_exists():
    assert all((EVAL / name).is_file() for name in REQUIRED_FILES)


def test_phase20_external_claims_have_no_evidence():
    manifest = json.loads((EVAL / "PHASE_20_ASSURANCE_MANIFEST.json").read_text())
    for claim in manifest["claims"]:
        if claim["status"] in {"not-validated", "not-claimed"}:
            assert claim["evidence"] == []
