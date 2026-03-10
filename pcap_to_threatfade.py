# pcap_to_threatfade.py - Convert real PCAP sessions to ThreatFade signals
from scapy.all import rdpcap, IP, TCP, UDP, Raw
import math
from collections import defaultdict
import json
from datetime import datetime

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

def pcap_to_signals(pcap_path):
    packets = rdpcap(pcap_path)
    print(f"[✓] Loaded {len(packets)} packets")
    
    sessions = defaultdict(list)
    
    for pkt in packets:
        if IP in pkt and Raw in pkt and (TCP in pkt or UDP in pkt):
            payload = pkt[Raw].load
            proto = 'TCP' if TCP in pkt else 'UDP'
            key = (pkt[IP].src, pkt[IP].dst, proto,
                   pkt[TCP].sport if TCP in pkt else pkt[UDP].sport,
                   pkt[TCP].dport if TCP in pkt else pkt[UDP].dport)
            sessions[key].append((float(pkt.time), len(payload), payload))
    
    # Convert sessions to time-series signals (entropy per 60-sec window)
    timestamps = []
    entropy_values = []
    
    if sessions:
        min_time = min(min(t for t, _, _ in pkts) for pkts in sessions.values())
        max_time = max(max(t for t, _, _ in pkts) for pkts in sessions.values())
        
        current_time = int(min_time)
        while current_time < int(max_time):
            window_entropies = []
            window_size = 64  # 64-byte chunks
            
            for key, pkts in sessions.items():
                payloads_in_window = [p for t, _, p in pkts if current_time <= t < current_time + 60]
                if payloads_in_window:
                    combined = b''.join(payloads_in_window)
                    # Split into chunks and compute entropy
                    for i in range(0, len(combined), window_size):
                        chunk = combined[i:i+window_size]
                        ent = compute_entropy(chunk)
                        window_entropies.append(ent)
            
            if window_entropies:
                avg_entropy = sum(window_entropies) / len(window_entropies)
                timestamps.append(datetime.fromtimestamp(current_time).isoformat())
                entropy_values.append(float(round(avg_entropy, 4)))
            
            current_time += 60
    
    return timestamps, entropy_values

# Run
pcap_file = "data/pcaps/merlin_quic.pcapng"
print(f"\n[*] Converting {pcap_file} to ThreatFade signals...\n")
ts, vals = pcap_to_signals(pcap_file)

# Save as JSON for ThreatFade
data = {"timestamps": ts, "values": vals}
with open("real_c2_signal.json", "w") as f:
    json.dump(data, f, indent=2)

print(f"[✓] Saved {len(vals)} entropy points to real_c2_signal.json")
print(f"[*] Now run: python main.py --data real_c2_signal.json --export\n")
