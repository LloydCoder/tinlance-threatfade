# ThreatFade brand assets

These files are exact assets and tokens from the owner-supplied ThreatFade Signal Trace logo kit v1.0. The uploaded kit remains the authoritative master source.

## Rules
- Full-color logo only on Navy `#0B1220` or Paper `#F4F6F8`.
- Amber is reserved for the signal spike: `#F5A524` on dark and `#C27200` on light.
- Preserve SVG viewBox and aspect ratio. Never recolor, stretch, rotate, add shadows, or redraw the mark.
- The wordmark is outlined artwork; do not retype it.
- Clear space on every side equals the height of the T.
- Minimum widths: horizontal 140 px, stacked 96 px, wordmark 100 px, mark 24 px. Below 24 px use the icon tile.
- Inter is the UI/heading typeface; JetBrains Mono is for code and metrics.

## Exact supplied assets
- `assets/threatfade-mark-on-dark.svg` and `assets/threatfade-mark-on-light.svg`: exact supplied Signal Trace variants.
- `dashboard/assets/brand/threatfade-mark-on-dark.svg`: dashboard mark served at `/assets/brand/threatfade-mark-on-dark.svg`.
- `dashboard/assets/brand/favicon.svg`: exact supplied favicon.
- `dashboard/assets/brand/site.webmanifest`: PWA metadata using the shipped SVG favicon.
- `dashboard/assets/brand/brand.css` and `colors.json`: exact canonical CSS and machine-readable tokens.

The FastAPI application mounts only the dashboard's static `assets` directory at `/assets`. Authenticated API and tenant routes are unchanged.

## GitHub social preview
GitHub's repository-level social preview is a remote setting, not a tracked file. Upload the official 1280×640 PNG from the supplied kit under **Repository → Settings → General → Social preview** after review. This PR does not claim that remote setting was changed.
