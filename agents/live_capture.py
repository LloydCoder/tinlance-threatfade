"""Production live-capture adapter boundary.

The adapter uses Scapy/libpcap where available and converts packets into the
canonical SignalEvent schema. Capture privilege is deliberately isolated to
this module; the rest of the sensor runs as an unprivileged process.
"""
from __future__ import annotations

import platform
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from core.data_plane import SignalEvent, new_event


class CaptureUnavailable(RuntimeError):
    pass


class LiveCaptureAdapter:
    """Scapy/libpcap adapter with explicit lifecycle and bounded callbacks."""

    def __init__(self, *, sensor_id: str, tenant_id: str, interface: str,
                 emit: Callable[[SignalEvent], bool], snaplen: int = 2048):
        if not interface or len(interface) > 128:
            raise ValueError("invalid capture interface")
        if not 64 <= snaplen <= 65535:
            raise ValueError("invalid snaplen")
        self.sensor_id = sensor_id
        self.tenant_id = tenant_id
        self.interface = interface
        self.emit = emit
        self.snaplen = snaplen
        self._running = False
        self._packet_count = 0
        self._dropped = 0

    @staticmethod
    def platform_backend() -> str:
        return "npcap" if platform.system() == "Windows" else "libpcap/AF_PACKET"

    def _packet_to_event(self, packet) -> SignalEvent:
        protocol = "unknown"
        src_ip = dst_ip = None
        src_port = dst_port = None
        packets = 1
        metadata = {"capture_backend": self.platform_backend(), "interface": self.interface}
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
            if packet.haslayer(IP):
                ip = packet[IP]; src_ip, dst_ip = ip.src, ip.dst
                if packet.haslayer(TCP):
                    protocol = "tcp"; src_port, dst_port = int(packet[TCP].sport), int(packet[TCP].dport)
                elif packet.haslayer(UDP):
                    protocol = "udp"; src_port, dst_port = int(packet[UDP].sport), int(packet[UDP].dport)
            elif packet.haslayer(IPv6):
                ip = packet[IPv6]; src_ip, dst_ip = ip.src, ip.dst
        except Exception:
            metadata["parse_error"] = True
        metadata["captured_len"] = min(len(packet), self.snaplen)
        return new_event(self.sensor_id, self.tenant_id, "packet", observed_at=datetime.now(timezone.utc),
                         protocol=protocol, src_ip=src_ip, dst_ip=dst_ip,
                         src_port=src_port, dst_port=dst_port, packets=packets,
                         bytes_in=len(packet), metadata=metadata)

    def _on_packet(self, packet) -> None:
        self._packet_count += 1
        event = self._packet_to_event(packet)
        try:
            if not self.emit(event):
                self._dropped += 1
        except Exception:
            self._dropped += 1

    def run(self, *, stop_event=None, timeout: float = 1.0) -> None:
        try:
            from scapy.sendrecv import sniff
        except ImportError as exc:
            raise CaptureUnavailable("Scapy is required for live capture") from exc
        self._running = True
        try:
            sniff(iface=self.interface, prn=self._on_packet, store=False,
                  count=0, timeout=timeout, stop_filter=(lambda _: bool(stop_event and stop_event.is_set())))
        finally:
            self._running = False

    def stop(self) -> None:
        self._running = False

    def metrics(self) -> dict[str, int | bool | str]:
        return {"running": self._running, "packets": self._packet_count,
                "dropped": self._dropped, "backend": self.platform_backend()}
