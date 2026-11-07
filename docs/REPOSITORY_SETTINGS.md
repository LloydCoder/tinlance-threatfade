# GitHub repository settings

This page records the recommended GitHub About metadata and repository controls for ThreatFade. These settings live in GitHub repository configuration and are not changed by editing files in Git.

## About section

### Recommended description

> Evidence-first network threat detection and investigation for C2 quieting, LOTL activity changes and multi-domain signal anomalies.

This describes the repository's implemented purpose without repeating the former unqualified `0% FP rate` claim or labeling the current codebase an early research MVP.

### Website

The owner-supplied brand kit references `threatfade.com`. Set the GitHub Website field to `https://threatfade.com` only after the maintainer verifies that the domain resolves to the official ThreatFade destination, uses HTTPS, and presents current product information. Do not use a placeholder or unrelated Tinlance URL.

### Topics

Recommended topics (choose 8–10):

- `cybersecurity`
- `network-security`
- `threat-detection`
- `c2-detection`
- `detection-engineering`
- `pcap-analysis`
- `mitre-attack`
- `siem`
- `security-analytics`
- `python`

Remove broad or imprecise topics if they no longer describe the repository's maintained functionality.

## Social preview

Use the official source asset from the owner-supplied kit:

`03-social/github-social-preview-dark-1280x640.png`

Upload it under **Repository → Settings → General → Social preview**. Review the rendered crop at desktop and mobile widths. GitHub's social preview is a remote setting; a tracked file or README image does not prove that the setting has been configured.

## Branch protection / rulesets

The branch listing observed during the audit reported `protected: false` for `main`. The connected GitHub integration could not read the branch-protection endpoint (HTTP 403), so the effective protection state must be confirmed by a repository administrator.

Recommended `main` rules:

- Require pull requests before merging.
- Require the essential CI, security and supply-chain checks to pass.
- Require at least one independent approval when a reviewer is available; do not let an author approve their own pull request.
- Require CODEOWNERS review for changes to security, deployment, workflow and documentation-policy paths where practical.
- Dismiss stale approvals after new commits.
- Require branches to be up to date before merge if the team's release cadence can support it.
- Block force pushes and branch deletion.
- Apply rules to administrators, with a narrowly controlled emergency bypass if operationally necessary.
- Keep status-check names stable and remove obsolete required checks after workflow changes.

For a single-maintainer project, avoid a review requirement that makes all normal changes impossible to merge. Add an independent maintainer/reviewer or use a documented emergency exception rather than bypassing CI.

## Releases

The repository's latest published release observed during the audit is `v0.3.0`; the current source identifies itself as `v0.9.0-dev`. Keep those facts distinct.

Before publishing the next release:

1. Reconcile the changelog with the exact release contents.
2. Create a release from a reviewed, tested commit and an immutable tag.
3. Publish the image digest and verify its Cosign signature.
4. Verify the build provenance and SBOM attestations.
5. State external validation, customer deployment and certification limitations accurately.

The release workflow signs container images and verifies those signatures. Do not claim that a GitHub source archive or every attached release asset is signed unless its signature is separately generated and verified.

## OpenSSF Scorecard

No live OpenSSF Scorecard result was obtained as part of this audit. The repository score in the audit report is an internal documentation/repository-health estimate, not an official Scorecard score.

Run Scorecard using the official CLI or GitHub Action and review individual checks, especially Branch-Protection, Code-Review, Binary-Artifacts, Pinned-Dependencies, Token-Permissions, Signed-Releases, CI-Tests, Security-Policy, SAST and Vulnerabilities.

Official references:

- [OpenSSF Scorecard](https://scorecard.dev/)
- [Scorecard checks](https://github.com/ossf/scorecard)
- [GitHub community profile guidance](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/about-community-profiles-for-public-repositories)
