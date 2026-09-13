import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _config_version() -> str:
    text = (ROOT / "config.yaml").read_text(encoding="utf-8")
    match = re.search(r"^\s*version:\s*([^\n#]+)", text, re.MULTILINE)
    assert match, "config.yaml must expose a top-level branding version"
    return match.group(1).strip().strip('"\'')


def test_public_truth_manifest_matches_runtime_version():
    truth = json.loads((ROOT / "docs" / "public-truth.json").read_text(encoding="utf-8"))
    assert truth["version"] == "0.9.0-dev"
    assert truth["version"] == _config_version()
    assert set(truth["evidenceTaxonomy"]) == {
        "IMPLEMENTED",
        "TESTED",
        "VALIDATED",
        "EXPERIMENTAL",
        "PLANNED",
        "ADAPTER",
        "EXTERNAL-DEPENDENCY",
    }


def test_public_truth_contains_explicit_external_validation_boundary():
    truth = json.loads((ROOT / "docs" / "public-truth.json").read_text(encoding="utf-8"))
    external = next(item for item in truth["validation"] if item["id"] == "TF-EXT-V0")
    assert external["status"] == "PLANNED"
    assert "No external result is claimed" in external["resultBoundary"]


def test_public_truth_does_not_claim_native_vendor_integrations():
    truth = json.loads((ROOT / "docs" / "public-truth.json").read_text(encoding="utf-8"))
    for integration in truth["integrations"]:
        assert integration["type"] in {"EXPORT", "ADAPTER", "COMPATIBLE"}
