# ThreatFade brand assets

The owner-supplied **ThreatFade logo kit v1.0** is the authoritative brand source. The complete kit includes 24 SVG logo variants, PNG logo exports, browser/PWA icons, social graphics, document templates, a color system and an 11-page brand-guidelines PDF. The uploaded source archive is the design master; repository assets are selected deployable copies.

## Identity rules

- Direction A: Signal Trace — network noise fades out, one spike stands apart in amber, and the baseline continues.
- Full-color marks are used only on Navy `#0B1220` or Paper `#F4F6F8`.
- Amber is reserved for the spike: `#F5A524` on dark and `#C27200` on light.
- Preserve proportions and clear space. Never recolor, stretch, rotate, redraw, add shadows, shields or locks, or reset the outlined wordmark in another typeface.
- Clear space on each side equals the height of the T.
- Minimum widths: horizontal 140 px, stacked 96 px, wordmark 100 px, mark 24 px. Below 24 px use the icon tile.
- Typefaces: Inter for wordmark/headings/UI; JetBrains Mono for code and metrics only.

## Repository assets

- `assets/threatfade-mark-on-dark.svg` and `assets/threatfade-mark-on-light.svg`: official Signal Trace mark variants.
- `assets/threatfade-wordmark-on-light.svg`: wordmark artwork used with the light-surface mark in the README.
- `dashboard/assets/brand/favicon.svg` and `safari-pinned-tab.svg`: browser identity assets.
- `dashboard/assets/brand/site.webmanifest`: current PWA metadata.
- `dashboard/assets/brand/brand.css` and `colors.json`: dashboard theme tokens.
- `colors.json`: machine-readable project palette.

The dashboard serves public brand assets from `/assets/brand/`; the FastAPI application mounts this directory independently of authenticated API routes.

## Social preview

GitHub's repository social preview is a remote repository setting, not a tracked file. Use the supplied `03-social/github-social-preview-dark-1280x640.png` asset from the master kit. Upload it under **Repository → Settings → General → Social preview** after checking the preview crop. The repository cannot prove that the remote setting has been applied merely because the source image exists in the kit.

## Document templates

Use the official assets in `04-templates/` from the master kit for reports, letterhead, presentations, business cards and email signatures. Preserve the supplied layout and replace only bracketed placeholders. The email-signature image must be hosted at a stable public URL before embedding it in Gmail or Outlook.

For print, request a printer proof and add 3 mm bleed where the printer requires it; the supplied business-card template has no bleed. Complete a trademark search before any trademark registration or launch claim.
