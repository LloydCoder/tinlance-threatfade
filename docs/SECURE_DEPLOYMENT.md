# ThreatFade Secure Deployment & Supply Chain

## Security objective

Group 7 establishes a reproducible build chain in which source changes are tested, container dependencies are pinned, SBOMs are generated and scanned, production images are published by immutable commit tags, and successful main-branch releases receive signed GitHub/Sigstore attestations.

GitHub artifact attestations bind artifacts to the workflow, repository, commit and build environment and can include SBOM attestations. GitHub documents artifact attestations as a supply-chain integrity mechanism and describes reusable workflows plus attestations as a path toward SLSA Build Level 3.

References:
- https://docs.github.com/en/actions/concepts/security/artifact-attestations
- https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating
- https://slsa.dev/spec/v1.2/provenance

## Build controls

- GitHub Actions are referenced by immutable 40-character commit SHA rather than mutable action tags.
- Docker base image is pinned to a content digest.
- `.dockerignore` excludes Git metadata, local environments, caches, recovery artifacts and secret-like files from the build context.
- Container runs as a dedicated non-root user.
- Linux capabilities are dropped at runtime.
- Kubernetes enables `RuntimeDefault` seccomp and disables privilege escalation.
- Kubernetes root filesystem is read-only; required writable paths are isolated `emptyDir` volumes.
- Kubernetes service-account token automount is disabled.
- Production image pulls use `Always` and release rendering requires an immutable image digest.

Docker recommends digest-pinning base images because tags are mutable and do not guarantee that future builds consume the same bytes. Kubernetes likewise documents digests as immutable image identifiers while tags can move.

References:
- https://docs.docker.com/build/building/best-practices/
- https://kubernetes.io/docs/concepts/containers/images/

## SBOM and vulnerability gates

The supply-chain workflow builds the container, generates an SPDX JSON SBOM with Syft, scans the SBOM with Anchore, and runs Trivy configuration scanning against Docker/Kubernetes configuration. A high-severity or critical vulnerability finding is a release failure unless it is explicitly treated as unfixed by the scanner policy.

References:
- https://github.com/anchore/sbom-action
- https://github.com/anchore/scan-action
- https://github.com/aquasecurity/trivy-action
- https://trivy.dev/docs/latest/scanner/misconfiguration/config/config/

## Provenance and attestations

Main-branch release builds are pushed to GHCR under a commit-derived tag:

`ghcr.io/lloydcoder/tinlance-threatfade:sha-<commit>`

The digest returned by the build is then used as the attestation subject. The workflow generates:

1. SLSA build provenance attestation.
2. SPDX SBOM attestation.
3. Registry-pushed attestation records.

GitHub's current `actions/attest` supports provenance and SBOM modes and uses OIDC-backed signing.

Reference: https://github.com/actions/attest

## Kubernetes network boundary

The workload has a NetworkPolicy that restricts ingress to TCP/8080, permits DNS resolution, and limits outbound traffic to HTTPS plus the PostgreSQL port used by the deployment. In a production cluster, the database egress rule should be narrowed further to the provider's exact database CIDR or namespace selector.

Kubernetes documents that without NetworkPolicies, pods are otherwise allowed ingress and egress by default; default-deny policies are therefore an important isolation primitive.

Reference: https://kubernetes.io/docs/concepts/services-networking/network-policies/

## Production image rendering

`deploy/kubernetes/deployment.yaml` is the generic deploy reference and uses the current release version. Production promotion must use `scripts/render_production_manifest.py` with an image reference containing a valid `@sha256:<64-hex>` digest. The renderer refuses mutable or malformed image references.

Example:

```text
python scripts/render_production_manifest.py \
  ghcr.io/lloydcoder/tinlance-threatfade:0.7.0@sha256:<release-digest> \
  deploy/kubernetes/production/rendered.yaml
```

The resulting rendered manifest, not the mutable tag reference, is the production deployment artifact.

## Secret-management boundary

No production credentials are stored in Git, Docker layers or Kubernetes manifests. Kubernetes receives runtime secrets through `secretKeyRef`; CI uses ephemeral `GITHUB_TOKEN` credentials for package publication and OIDC-backed attestations. Database recovery credentials remain environment-scoped as established in Group 6.

The repository deliberately does not implement a vendor-specific external secrets manager because that would couple the core project to AWS/GCP/Azure/Vault/Cloudflare infrastructure. The production platform must bind Kubernetes Secrets to the organization's approved secret-management system and rotation policy.

## Release gate

A release is considered Group 7 compliant only when all of the following are green:

- core Python test matrix
- PostgreSQL integrity and restore drill
- dependency audit
- CodeQL security-extended analysis
- Gitleaks secret scan
- supply-chain architecture validator
- Docker build
- SPDX SBOM generation
- SBOM vulnerability scan
- Trivy Docker/Kubernetes configuration scan
- digest-pinned production renderer test
- main-branch image provenance attestation
- main-branch SBOM attestation

Attestation publication is intentionally limited to trusted main-branch pushes; pull requests build and scan without package-write or attestation privileges.
