from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "dashboard" / "assets" / "brand"


def _git_blob_sha(path: Path) -> str:
    content = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\\0" + content).hexdigest()


def test_dashboard_uses_official_signal_trace_logo_and_palette() -> None:
    html = (ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    assert 'src="/assets/brand/threatfade-mark-on-dark.svg"' in html
    assert 'href="/assets/brand/favicon.svg"' in html
    assert 'href="/assets/brand/site.webmanifest"' in html
    assert "--accent:var(--tf-signal)" in html
    assert "#59e1cf" not in html
    assert ">TF</div>" not in html
    assert "<b>ThreatFade</b>" not in html
    assert "var(--tf-signal)" in html


def test_dashboard_uses_byte_exact_official_logo_and_favicon() -> None:
    # Git blob hashes pin these assets to the owner-supplied v1.0 logo kit.
    assert _git_blob_sha(BRAND / "threatfade-mark-on-dark.svg") == "2cb9dce394584932bd29c74ca46804e2fd99e52f"
    assert _git_blob_sha(BRAND / "favicon.svg") == "26d5b5e1e9bfda83f85fcb0057771bec9605a84e"


def test_public_brand_assets_exist_and_manifest_is_consistent() -> None:
    assert (BRAND / "threatfade-mark-on-dark.svg").is_file()
    assert (BRAND / "favicon.svg").is_file()
    manifest = json.loads((BRAND / "site.webmanifest").read_text(encoding="utf-8"))
    assert manifest["name"] == "ThreatFade"
    assert manifest["theme_color"] == "#0B1220"
    assert manifest["icons"][0]["src"] == "/assets/brand/favicon.svg"
    css = (BRAND / "brand.css").read_text(encoding="utf-8")
    assert "--tf-signal:#F5A524" in css
    assert "--tf-font-sans:\"Inter\"" in css


def test_api_mounts_only_dashboard_static_assets_for_brand_resources() -> None:
    api = (ROOT / "api.py").read_text(encoding="utf-8")
    assert 'app.mount("/assets", StaticFiles(directory="dashboard/assets"), name="public-brand-assets")' in api
