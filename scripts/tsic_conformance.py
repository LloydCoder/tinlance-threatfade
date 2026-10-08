from __future__ import annotations

import base64
import json
from urllib.request import Request, urlopen

TSIC_REVISION = "656a4ecff1f6ab3bc416d3cc9ae647636391e94d"
REQUIRED = {
    "identity-context",
    "event-envelope",
    "delivery-semantics",
    "trace-context",
    "economic-attribution",
}


def fetch_json(path: str) -> dict:
    url = f"https://api.github.com/repos/LloydCoder/tinlance-system-integration/contents/{path}?ref={TSIC_REVISION}"
    request = Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "tinlance-threatfade-tsic"},
    )
    with urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError(f"TSIC contents API returned HTTP {response.status}: {url}")
        payload = json.load(response)
    return json.loads(base64.b64decode(payload["content"].replace("\n", "")).decode("utf-8"))


def main() -> None:
    manifest = fetch_json("manifests/ecosystem.json")
    adapter = fetch_json("integrations/threatfade/adapter.json")
    registry = fetch_json("catalog/contracts/registry.json")

    system = next(item for item in manifest["systems"] if item["id"] == "threatfade")
    assert system["repository"] == "LloydCoder/tinlance-threatfade"
    assert system["governance_role"] == "security_engineering_authority"

    assert adapter["source_system"] == "tsic"
    assert adapter["target_system"] == "threatfade"
    assert adapter["status"] == "reference-contract"
    assert {item["tsic_contract"] for item in adapter["contract_bindings"]} == REQUIRED
    assert {item["id"] for item in registry["contracts"]} >= REQUIRED
    assert adapter["authority"]["integration_contracts"] == "tsic"
    assert adapter["authority"]["threat_detection_response"] == "threatfade"
    assert adapter["authority"]["execution_authority"] == "agent-platform"

    required_invariants = {
        "detection_is_not_execution_authority",
        "evidence_and_provenance_are_preserved",
        "tenant_context_is_immutable",
        "tsic_remains_integration_authority",
        "agent-platform-remains-execution-authority",
    }
    assert set(adapter["invariants"]) == required_invariants

    print(f"PASS TSIC-31 ThreatFade conformance: revision={TSIC_REVISION}")


if __name__ == "__main__":
    main()
