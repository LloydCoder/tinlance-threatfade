from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "dashboard" / "assets" / "brand"


def test_dashboard_uses_official_signal_trace_logo_and_palette() -> None:
    html = (ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    assert 'src="/assets/brand/threatfade-mark-on-dark.svg"' in html
    assert 'href="/assets/brand/favicon.svg"' in html
    assert 'href="/assets/brand/site.webmanifest"' in html
    assert "--accent:#F5A524" in html
    assert "#59e1cf" not in html
    assert ">TF</div>" not in html


def test_public_brand_assets_exist_and_manifest_is_consistent() -> None:
    assert (BRAND / "threatfade-mark-on-dark.svg").is_file()
    assert (BRAND / "favicon.svg").is_file()
    manifest = json.loads((BRAND / "site.webmanifest").read_text(encoding="utf-8"))
    assert manifest["name"] == "ThreatFade"
    assert manifest["theme_color"] == "#0B1220"
    assert manifest["icons"][0]["src"] == "/assets/brand/favicon.svg"
