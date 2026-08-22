"""Static acceptance gate for Group 7 supply-chain controls."""
from __future__ import annotations

from pathlib import Path
import re
import yaml

ROOT = Path(__file__).resolve().parents[1]


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert_true("ARG PYTHON_BASE_TAG=3.12.14-slim-trixie" in dockerfile, "Python base tag must target the current patched 3.12 release")
    assert_true("ARG PYTHON_BASE_DIGEST" in dockerfile and "FROM python:${PYTHON_BASE_TAG}@${PYTHON_BASE_DIGEST}" in dockerfile, "Python base image must be injected by immutable digest")
    assert_true("USER threatfade" in dockerfile, "container must run as non-root")
    assert_true("org.opencontainers.image.source" in dockerfile, "OCI source label required")
    assert_true("HEALTHCHECK" in dockerfile, "container healthcheck required")
    assert_true("--upgrade pip" in dockerfile, "pip must be upgraded during image build")

    workflow_dir = ROOT / ".github" / "workflows"
    workflow_text = "\n".join(p.read_text(encoding="utf-8") for p in workflow_dir.glob("*.yml"))
    action_refs = re.findall(r"uses:\s*([^\s]+)@([^\s]+)", workflow_text)
    unpinned = [f"{name}@{ref}" for name, ref in action_refs if not re.fullmatch(r"[0-9a-f]{40}", ref)]
    assert_true(not unpinned, f"all GitHub Actions must be SHA pinned: {unpinned}")
    assert_true("docker buildx imagetools inspect python:3.12.14-slim-trixie" in workflow_text, "CI must resolve the current base image digest")
    assert_true("PYTHON_BASE_DIGEST" in workflow_text, "CI must pass the resolved base digest into Docker builds")

    manifest = list(yaml.safe_load_all((ROOT / "deploy/kubernetes/deployment.yaml").read_text(encoding="utf-8")))
    deployment = next(item for item in manifest if item.get("kind") == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    image = container["image"]
    assert_true("@sha256:" not in image or re.search(r"@sha256:[0-9a-f]{64}$", image) is not None, "if deployment uses a digest it must be valid")
    assert_true(":latest" not in image, "latest image tag is forbidden")
    assert_true(re.fullmatch(r"[A-Za-z0-9./_-]+:[0-9]+\.[0-9]+\.[0-9]+", image) is not None or "@sha256:" in image, "deployment image must use a release version or immutable digest")
    assert_true(pod.get("automountServiceAccountToken") is False, "service account token automount must be disabled")
    sc = container["securityContext"]
    assert_true(sc.get("allowPrivilegeEscalation") is False, "privilege escalation must be disabled")
    assert_true(sc.get("readOnlyRootFilesystem") is True, "root filesystem must be read-only")
    assert_true(set(sc.get("capabilities", {}).get("drop", [])) == {"ALL"}, "all Linux capabilities must be dropped")
    assert_true(pod.get("securityContext", {}).get("runAsNonRoot") is True, "pod must require non-root")

    kinds = {item.get("kind") for item in manifest}
    assert_true("NetworkPolicy" in kinds, "deployment must include NetworkPolicy")
    assert_true("ServiceAccount" in kinds, "deployment must include dedicated ServiceAccount")

    template = (ROOT / "deploy/kubernetes/production/deployment.template.yaml").read_text(encoding="utf-8")
    assert_true("${THREATFADE_IMAGE}" in template, "production template must require an injected image")
    assert_true("imagePullPolicy: Always" in template, "production template must always pull the selected digest")

    renderer = (ROOT / "scripts/render_production_manifest.py").read_text(encoding="utf-8")
    assert_true("@sha256:[0-9a-f]{64}" in renderer, "production renderer must enforce digest syntax")

    print("Group 7 supply-chain and runtime security gate: OK")


if __name__ == "__main__":
    main()
