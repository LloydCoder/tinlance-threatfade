"""Render the Kubernetes production image template only with a digest-pinned image."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
IMAGE_RE = re.compile(r"^[A-Za-z0-9./_-]+(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: render_production_manifest.py <image@sha256:digest> <output>")
    image, output = sys.argv[1], Path(sys.argv[2])
    if not IMAGE_RE.fullmatch(image):
        raise SystemExit("production image must be an immutable OCI digest reference")
    template = (ROOT / "deploy/kubernetes/production/deployment.template.yaml").read_text(encoding="utf-8")
    rendered = template.replace("${THREATFADE_IMAGE}", image)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(f"rendered digest-pinned production manifest: {output}")


if __name__ == "__main__":
    main()
