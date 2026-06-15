"""
ThreatFade Live Network Monitor
Captures live traffic from a network interface and runs fade detection.
Supports Linux, Windows, macOS.
"""

import time
import math
import threading
from datetime import datetime
from collections import defaultdict, deque
from typing import Callable, Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def is_live_available():
    return SCAPY_AVAILABLE


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            ent -= p * math.log2(p)
    return ent


class LiveMonitor:
    """
    Captures live packets from a network interface.
    Converts packet stream into entropy time-series for ThreatFade.
    """

    def __init__(self, interface: str, window_sec: int = 10):
        self.interface = interface
        self.window_sec = window_sec
        self.packet_buffer = deque()
        self.running = False
        self._lock = threading.Lock()

    def _packet_handler(self, pkt):
        if IP in pkt and Raw in pkt and (TCP in pkt or UDP in pkt):
            with self._lock:
                self.packet_buffer.append((time.time(), pkt[Raw].load))

    def start_capture(self, duration_sec: int = 60):
        """Capture packets for a fixed duration."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy not installed. Run: pip install scapy")

        print(f"[*] Capturing on {self.interface} for {duration_sec}s ...")
        self.running = True
        self.packet_buffer.clear()

        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                timeout=duration_sec,
                store=False,
            )
        except PermissionError:
            print(f"[!] Permission denied on {self.interface}.")
            print(f"[!] Live capture requires root/sudo on Linux.")
            print(f"[!] Try: sudo python main.py --live {self.interface}")
            print(f"[!] Note: Not supported in containers (Codespaces/Docker).")
            raise
        self.running = False
        print(f"[+] Captured {len(self.packet_buffer)} packets")

    def to_entropy_signals(self, interval_sec: int = 10):
        """Convert captured packets to entropy time-series."""
        with self._lock:
            packets = list(self.packet_buffer)

        if not packets:
            return list(range(20)), [0.5] * 20

        start_t = packets[0][0]
        end_t = packets[-1][0]

        bins = defaultdict(list)
        for ts, payload in packets:
            bin_key = int((ts - start_t) / interval_sec)
            bins[bin_key].append(payload)

        max_bin = max(bins.keys()) + 1
        timestamps = []
        entropy_values = []

        for i in range(max_bin):
            payloads = bins.get(i, [])
            if payloads:
                combined = b"".join(payloads)
                ent = _byte_entropy(combined)
            else:
                ent = 0.0
            timestamps.append(i * interval_sec)
            entropy_values.append(ent)

        print(f"[+] Extracted {len(entropy_values)} entropy windows")
        return timestamps, entropy_values
