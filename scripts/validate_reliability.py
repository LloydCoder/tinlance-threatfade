"""Static/runtime acceptance gate for Group 5 reliability controls."""
from __future__ import annotations

from pathlib import Path
import yaml

from core.health import readiness_state
from core.reliability import CircuitBreaker, RetryPolicy, retry_call


def main() -> None:
    ready, checks = readiness_state(draining=False)
    assert ready, checks
    assert checks["storage"]["status"] == "ok"

    attempts = {"count": 0}
    def transient():
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise TimeoutError("fixture")
        return True
    assert retry_call(transient, policy=RetryPolicy(attempts=2, base_delay=0, jitter=0))

    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=1)
    try:
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fixture")))
    except RuntimeError:
        pass
    assert breaker.state == "open"

    manifest = list(yaml.safe_load_all(Path("deploy/kubernetes/deployment.yaml").read_text(encoding="utf-8")))
    deployment = next(item for item in manifest if item.get("kind") == "Deployment")
    pdb = next(item for item in manifest if item.get("kind") == "PodDisruptionBudget")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["startupProbe"]["httpGet"]["path"] == "/healthz"
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert container["readinessProbe"]["httpGet"]["path"] == "/ready"
    assert deployment["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] == 0
    assert pdb["spec"]["minAvailable"] == 1
    print("Group 5 reliability gate: OK")


if __name__ == "__main__":
    main()
