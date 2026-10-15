from __future__ import annotations

import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

TSIC_REVISION = "656a4ecff1f6ab3bc416d3cc9ae647636391e94d"
REQUIRED = {
    "identity-context",
    "event-envelope",
    "delivery-semantics",
    "trace-context",
    "economic-attribution",
}
RETRYABLE_HTTP_STATUSES = {429, 500, 502, 503, 504}


def fetch_json(path: str) -> dict:
    """Fetch a file from the immutable TSIC revision without GitHub REST API quotas."""
    url = (
        "https://raw.githubusercontent.com/"
        f"LloydCoder/tinlance-system-integration/{TSIC_REVISION}/{path}"
    )
    for attempt in range(3):
        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "tinlance-threatfade-tsic",
            },
        )
        try:
            with urlopen(request, timeout=20) as response:
                if response.status != 200:
                    raise RuntimeError(
                        f"TSIC raw-content fetch returned HTTP {response.status}: {url}"
                    )
                payload = json.load(response)
                if not isinstance(payload, dict):
                    raise RuntimeError(f"TSIC contract must be a JSON object: {url}")
                return payload
        except HTTPError as exc:
            if exc.code not in RETRYABLE_HTTP_STATUSES or attempt == 2:
                raise RuntimeError(
                    f"TSIC raw-content fetch failed with HTTP {exc.code}: {url}"
                ) from exc
            retry_after = exc.headers.get("Retry-After", "")
            delay = int(retry_after) if retry_after.isdigit() else 2**attempt
            time.sleep(min(max(delay, 1), 30))
        except URLError as exc:
            if attempt == 2:
                raise RuntimeError(f"TSIC raw-content fetch failed: {url}") from exc
            time.sleep(2**attempt)
    raise RuntimeError(f"TSIC raw-content fetch exhausted retries: {url}")


def main() -> None:
    manifest = fetch_json("manifests/ecosystem.json")
    adapter = fetch_json("integrations/threatfade/adapter.json")
    registry = fetch_json("catalog/contracts/registry.json")

    system = next(item for item in manifest["systems"] if item["id"] == "threatfade")
    assert system["repository"] == "LloydCoder/tinlance-threatfade"
    assert system["governance_role"] == "domain_security_authority"

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
