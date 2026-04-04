"""
ThreatFade™ SIEM Exporter
Exports fade detection results to SIEM-friendly formats.
Supports: JSON (Splunk/ELK ready), CEF, Syslog (file).

© Tinlance Limited 2026 - Apache 2.0
"""

import json
import datetime
from pathlib import Path
from typing import Dict, List, Union

class SIEMExporter:
    def __init__(self, output_dir: str = "reports/siem"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, 
               result: Union[Dict, List[Dict]], 
               source_name: str = "unknown_pcap",
               format_type: str = "json") -> str:
        """Export detection result(s) to chosen format."""
        if isinstance(result, dict):
            events = [result]
        else:
            events = result

        if not events:
            return "No detection events to export."

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threatfade_{source_name}_{ts}"

        if format_type.lower() == "json":
            return self._export_json(events, filename)
        elif format_type.lower() == "cef":
            return self._export_cef(events, filename)
        elif format_type.lower() == "syslog":
            return self._export_syslog(events, filename)
        else:
            return f"Unsupported format '{format_type}'. Use: json, cef, syslog"

    def _export_json(self, events: List[Dict], filename: str) -> str:
        payload = {
            "tool": "ThreatFade",
            "version": "0.2.0-beta",
            "exported_at": datetime.datetime.now().isoformat(),
            "total_events": len(events),
            "events": events
        }
        path = self.output_dir / f"{filename}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return f"✅ JSON exported → {path}"

    def _export_cef(self, events: List[Dict], filename: str) -> str:
        lines = []
        for ev in events:
            cef_line = (
                f"CEF:0|Tinlance|ThreatFade|0.2.0|fade-detection|"
                f"Threat Fade Detected|"
                f"{self._get_severity(ev.get('confidence', 'MEDIUM'))}|"
                f"confidence={ev.get('confidence', 'MEDIUM')} "
                f"z_score={ev.get('z_score', 0):.2f} "
                f"mitre_ttp={ev.get('mitre_ttp', 'T0000')} "
                f"detected={ev.get('detected', False)}"
            )
            lines.append(cef_line)
        path = self.output_dir / f"{filename}.cef"
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return f"✅ CEF exported → {path}"

    def _export_syslog(self, events: List[Dict], filename: str) -> str:
        lines = []
        for ev in events:
            line = (
                f"{datetime.datetime.now().isoformat()} ThreatFade: "
                f"[{ev.get('confidence', 'MEDIUM')}] Fade detected | "
                f"Z-score: {ev.get('z_score', 0):.2f} | "
                f"TTP: {ev.get('mitre_ttp', 'N/A')}"
            )
            lines.append(line)
        path = self.output_dir / f"{filename}.log"
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return f"✅ Syslog exported → {path}"

    def _get_severity(self, confidence: str) -> int:
        mapping = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3, "INFO": 1}
        return mapping.get(confidence.upper(), 5)


if __name__ == "__main__":
    print("✅ SIEMExporter module loaded successfully.")
