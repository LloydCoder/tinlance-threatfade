"""Static architecture gate for the governed evaluation corpus contract."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = (ROOT / "core" / "corpus.py").read_text(encoding="utf-8")
METHODOLOGY = (ROOT / "docs" / "evaluation" / "corpus-methodology.md").read_text(encoding="utf-8")

for marker in (
    "class CorpusEntry",
    "class CorpusManifest",
    "def validate_split_separation",
    "sha256",
    "source_reference",
    "license_reference",
    "label_confidence",
    "chain_of_custody_reference",
):
    assert marker in CORPUS, f"corpus contract missing marker: {marker}"

for marker in ("development", "tuning", "holdout", "blind", "SHA-256", "Split policy"):
    assert marker in METHODOLOGY, f"corpus methodology missing marker: {marker}"

print("corpus governance architecture: OK")
