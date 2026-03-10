# pcap_test.py - quick & dirty
from scapy.all import rdpcap, IP, TCP, UDP, Raw
import math
from collections import defaultdict
import json
import sys
from decimal import Decimal

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    count = len(data)
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    for f in freq:
        if f > 0:
            p = f / count
            entropy -= p * math.log2(p)
    return entropy

def extract_sessions(pcap_path):
    try:
        packets = rdpcap(pcap_path)
        print(f"[✓] Loaded {len(packets)} packets from {pcap_path}")
    except Exception as e:
        print(f"[!] Error reading pcap: {e}")
        return {}

    sessions = defaultdict(list)

    for pkt in packets:
        if IP in pkt and Raw in pkt and (TCP in pkt or UDP in pkt):
            payload = pkt[Raw].load
            proto = 'TCP' if TCP in pkt else 'UDP'
            key = (pkt[IP].src, pkt[IP].dst, proto,
                   pkt[TCP].sport if TCP in pkt else pkt[UDP].sport,
                   pkt[TCP].dport if TCP in pkt else pkt[UDP].dport)
            sessions[key].append((float(pkt.time), payload))  # Convert to float

    return sessions

# Main
if len(sys.argv) < 2:
    print("Usage: python pcap_test.py <pcap_file>")
    sys.exit(1)

pcap_file = sys.argv[1]
print(f"\n[*] Analyzing {pcap_file}...\n")
sessions = extract_sessions(pcap_file)

results = []
for key, pkts in sessions.items():
    if len(pkts) < 5: 
        continue
    timestamps = [t for t, _ in pkts]
    payloads = [p for _, p in pkts]
    combined = b''.join(payloads)
    ent = compute_entropy(combined)
    
    if len(timestamps) > 1:
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)
    else:
        avg_interval = 0

    results.append({
        "session": f"{key[0]} -> {key[1]}",
        "protocol": key[2],
        "packets": len(pkts),
        "entropy": float(round(ent, 4)),
        "avg_interval_sec": float(round(avg_interval, 2)),
        "note": "Likely C2 beacon" if (ent < 5 and avg_interval > 10) else "Normal traffic"
    })

print(f"\n[✓] Found {len(results)} active sessions\n")
for r in results[:10]:  # Print first 10
    print(json.dumps(r))
print(f"\n... and {len(results) - 10} more sessions")
