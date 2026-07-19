#!/usr/bin/env python3
"""
Generate synthetic but realistic attack PCAPs for ThreatFade testing.
These mimic real C2 behavior patterns.
"""

from scapy.all import *
import random
import time

def generate_c2_beacon_pcap(filename, duration_sec=300, beacon_interval=30, jitter=5):
    """Generate Cobalt Strike-like beaconing PCAP"""
    packets = []
    base_time = time.time()
    
    # Victim and C2 IPs
    victim_ip = "192.168.1.100"
    c2_ip = "185.220.101.42"
    
    for i in range(duration_sec):
        # Beacon with jitter
        if i % beacon_interval == 0:
            jittered = random.randint(-jitter, jitter)
            actual_time = base_time + i + jittered
            
            # HTTPS beacon (TLS handshake + encrypted data)
            pkt = IP(src=victim_ip, dst=c2_ip)/TCP(sport=random.randint(40000, 50000), dport=443)/Raw(load=b'\x16\x03\x01' + b'\x00' * 200)
            pkt.time = actual_time
            packets.append(pkt)
            
            # C2 response
            resp = IP(src=c2_ip, dst=victim_ip)/TCP(sport=443, dport=pkt[TCP].sport)/Raw(load=b'\x16\x03\x01' + b'\x00' * 500)
            resp.time = actual_time + 0.1
            packets.append(resp)
        
        # Background noise (occasional DNS, HTTP)
        if random.random() < 0.05:
            noise = IP(src=victim_ip, dst="8.8.8.8")/UDP(sport=53, dport=53)/DNS()
            noise.time = base_time + i
            packets.append(noise)
    
    wrpcap(filename, packets)
    print(f"Generated {filename}: {len(packets)} packets, {duration_sec}s duration")

def generate_dga_dns_pcap(filename, duration_sec=120):
    """Generate IcedID-like DGA DNS PCAP"""
    packets = []
    base_time = time.time()
    victim_ip = "192.168.1.100"
    
    # DGA domains
    tlds = [".com", ".net", ".org", ".info", ".biz"]
    for i in range(0, duration_sec, 10):  # Every 10 seconds
        domain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=15)) + random.choice(tlds)
        pkt = IP(src=victim_ip, dst="8.8.8.8")/UDP(sport=random.randint(40000, 50000), dport=53)/DNS(
            qd=DNSQR(qname=domain)
        )
        pkt.time = base_time + i + random.randint(-2, 2)
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"Generated {filename}: {len(packets)} packets, {duration_sec}s duration")

def generate_data_exfil_pcap(filename, duration_sec=180):
    """Generate data exfiltration PCAP (T1048)"""
    packets = []
    base_time = time.time()
    victim_ip = "192.168.1.100"
    exfil_ip = "45.142.214.191"
    
    for i in range(0, duration_sec, 15):  # Bursts every 15s
        # Exfiltration burst
        for j in range(random.randint(5, 15)):
            pkt = IP(src=victim_ip, dst=exfil_ip)/TCP(
                sport=random.randint(40000, 50000), 
                dport=8080
            )/Raw(load=b'EXFIL' + b'A' * random.randint(100, 1000))
            pkt.time = base_time + i + j * 0.1
            packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"Generated {filename}: {len(packets)} packets, {duration_sec}s duration")

def generate_benign_baseline_pcap(filename, duration_sec=300):
    """Generate benign traffic for false-positive testing"""
    packets = []
    base_time = time.time()
    victim_ip = "192.168.1.100"
    
    for i in range(duration_sec):
        # Regular web browsing
        if random.random() < 0.3:
            pkt = IP(src=victim_ip, dst="93.184.216.34")/TCP(
                sport=random.randint(40000, 50000), 
                dport=443
            )/Raw(load=b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
            pkt.time = base_time + i
            packets.append(pkt)
        
        # DNS queries
        if random.random() < 0.1:
            sites = ["google.com", "github.com", "stackoverflow.com", "reddit.com"]
            pkt = IP(src=victim_ip, dst="8.8.8.8")/UDP(sport=53, dport=53)/DNS(
                qd=DNSQR(qname=random.choice(sites))
            )
            pkt.time = base_time + i
            packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"Generated {filename}: {len(packets)} packets, {duration_sec}s duration")

# Generate all test PCAPs
print("=== Generating Attack PCAPs ===")
generate_c2_beacon_pcap("test_pcaps/real/synthetic_cobalt_strike.pcap", duration_sec=300, beacon_interval=30)
generate_dga_dns_pcap("test_pcaps/real/synthetic_icedid_dga.pcap", duration_sec=120)
generate_data_exfil_pcap("test_pcaps/real/synthetic_exfiltration.pcap", duration_sec=180)
generate_benign_baseline_pcap("test_pcaps/real/synthetic_benign.pcap", duration_sec=300)

print("\n=== Done ===")
