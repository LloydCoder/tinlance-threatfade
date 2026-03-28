# tools/pcap_to_signal.py
from scapy.all import rdpcap
from datetime import datetime, timedelta
import argparse
import json

def pcap_to_signal(pcap_file, interval_sec=60):
    packets = rdpcap(pcap_file)
    start_time = packets[0].time
    bins = {}
    
    for pkt in packets:
        ts = datetime.fromtimestamp(float(pkt.time))
        bin_time = ts - timedelta(seconds=(ts - datetime.fromtimestamp(start_time)).seconds % interval_sec)
        bin_key = bin_time.strftime("%Y-%m-%d %H:%M:%S")
        bins[bin_key] = bins.get(bin_key, 0) + 1  # count packets
    
    # Convert to sorted list
    timestamps = []
    values = []
    for t in sorted(bins.keys()):
        timestamps.append(datetime.strptime(t, "%Y-%m-%d %H:%M:%S"))
        values.append(bins[t])
    
    return timestamps, values

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Path to .pcap file")
    parser.add_argument("--output", default="signal.json", help="Output JSON")
    args = parser.parse_args()
    
    ts, vals = pcap_to_signal(args.pcap)
    data = {"timestamps": [t.isoformat() for t in ts], "values": vals}
    
    with open(args.output, "w") as f:
        json.dump(data, f, indent=2)
    
    print(f"Saved {len(vals)} points to {args.output}")
