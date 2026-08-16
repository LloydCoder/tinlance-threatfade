from pathlib import Path

path = Path("api.py")
text = path.read_text(encoding="utf-8")
import_line = "from core.enterprise_routes import router as enterprise_router\n"
if import_line not in text:
    anchor = "from core.enterprise import AUDIT, authenticate, authorize, require_tenant, slo_targets\n"
    if anchor not in text:
        raise SystemExit("enterprise import anchor not found")
    text = text.replace(anchor, anchor + import_line, 1)
include_line = "app.include_router(enterprise_router)\n\n"
if include_line not in text:
    anchor = "@app.get(\"/\")\ndef dashboard(): return FileResponse(\"dashboard/index.html\")\n"
    if anchor not in text:
        raise SystemExit("dashboard route anchor not found")
    text = text.replace(anchor, include_line + anchor, 1)
path.write_text(text, encoding="utf-8")
print("api.py enterprise router integration complete")
