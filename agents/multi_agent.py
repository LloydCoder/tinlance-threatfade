"""
ThreatFade Multi-Agent Coordinator
Runs endpoint agents across multiple hosts and aggregates results.
"""

import time
import threading
import platform
from datetime import datetime
from typing import List, Dict, Any

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.fade_engine import detect_fade
from core.alert_dedup import AlertDeduplicator
from mitre.rule_parser import match_mitre_ttp
from agents.endpoint_agent import (
    collect_network_signals,
    collect_process_signals,
    normalize_signals,
)


class AgentResult:
    def __init__(self, agent_id, host, mode, result, mitre_ttp, duration):
        self.agent_id = agent_id
        self.host = host
        self.mode = mode
        self.result = result
        self.mitre_ttp = mitre_ttp
        self.duration = duration
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "host": self.host,
            "mode": self.mode,
            "timestamp": self.timestamp,
            "detected": self.result["detected"],
            "confidence": self.result["confidence"],
            "score": self.result["score"],
            "z_outlier": self.result["z_outlier"],
            "mitre_ttp": self.mitre_ttp,
            "duration_sec": self.duration,
        }


class MultiAgentCoordinator:
    """
    Coordinates multiple endpoint agents and aggregates detections.
    Supports parallel execution and alert deduplication across agents.
    """

    def __init__(self, dedup_window_sec: int = 300):
        self.agents = []
        self.results: List[AgentResult] = []
        self.dedup = AlertDeduplicator(window_sec=dedup_window_sec)
        self._lock = threading.Lock()

    def add_agent(self, agent_id: str, mode: str = "network",
                  duration_sec: int = 30, interval_sec: int = 5):
        self.agents.append({
            "id": agent_id,
            "mode": mode,
            "duration": duration_sec,
            "interval": interval_sec,
        })

    def _run_agent(self, agent_config: Dict):
        agent_id = agent_config["id"]
        mode = agent_config["mode"]
        duration = agent_config["duration"]
        interval = agent_config["interval"]
        host = platform.node()

        try:
            if mode == "network":
                timestamps, signals = collect_network_signals(duration, interval)
            else:
                timestamps, signals = collect_process_signals(duration, interval)

            if len(signals) < 12:
                return

            normalized = normalize_signals(signals)
            result = detect_fade(timestamps, normalized)
            mitre_ttp = match_mitre_ttp(result) if result["detected"] else "None"

            agent_result = AgentResult(
                agent_id=agent_id,
                host=host,
                mode=mode,
                result=result,
                mitre_ttp=mitre_ttp,
                duration=duration,
            )

            with self._lock:
                self.results.append(agent_result)

        except Exception as e:
            print(f"[!] Agent {agent_id} error: {e}")

    def run_all(self, parallel: bool = True):
        print(f"\n[*] Starting {len(self.agents)} agents "
              f"({'parallel' if parallel else 'sequential'}) ...")

        if parallel:
            threads = []
            for agent in self.agents:
                t = threading.Thread(target=self._run_agent, args=(agent,))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
        else:
            for agent in self.agents:
                self._run_agent(agent)

        print(f"[+] All agents complete. {len(self.results)} results collected.")

    def aggregate_report(self) -> Dict[str, Any]:
        total = len(self.results)
        detections = [r for r in self.results if r.result["detected"]]
        unique_ttps = list(set(r.mitre_ttp for r in detections if r.mitre_ttp != "None"))
        avg_score = (
            sum(r.result["score"] for r in self.results) / total
            if total > 0 else 0.0
        )

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_agents": total,
            "detections": len(detections),
            "detection_rate": f"{(len(detections)/total*100):.1f}%" if total > 0 else "0%",
            "unique_ttps": unique_ttps,
            "avg_score": round(avg_score, 4),
            "agents": [r.to_dict() for r in self.results],
        }
        return report

    def print_report(self):
        report = self.aggregate_report()
        print(f"\n{'=' * 56}")
        print(f"  Multi-Agent Coordination Report")
        print(f"{'=' * 56}")
        print(f"  Timestamp      : {report['timestamp']}")
        print(f"  Total agents   : {report['total_agents']}")
        print(f"  Detections     : {report['detections']}")
        print(f"  Detection rate : {report['detection_rate']}")
        print(f"  Avg score      : {report['avg_score']}")
        if report['unique_ttps']:
            print(f"  TTPs detected  : {', '.join(report['unique_ttps'])}")
        print(f"\n  Agent Results:")
        for a in report['agents']:
            status = "FADE" if a['detected'] else "CLEAN"
            print(f"  [{a['agent_id']}] {a['host']} | {a['mode']} | "
                  f"{status} | conf:{a['confidence']} | z:{a['z_outlier']:.2f}")
        print(f"{'=' * 56}\n")
        return report


if __name__ == "__main__":
    coordinator = MultiAgentCoordinator()
    coordinator.add_agent("agent-01", mode="network", duration_sec=60, interval_sec=5)
    coordinator.add_agent("agent-02", mode="process", duration_sec=60, interval_sec=5)
    coordinator.run_all(parallel=True)
    coordinator.print_report()
