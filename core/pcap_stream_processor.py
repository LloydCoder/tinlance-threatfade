"""Streaming PCAP processor for large captures."""
import time
import numpy as np
from typing import Iterator, Tuple, List, Dict, Any
from scapy.all import PcapReader, IP, TCP, UDP, Raw
from core.fade_engine import detect_fade
from mitre.rule_parser import match_mitre_ttp

def extract_packet_features(pkt) -> float:
    """Extract a single feature value from a packet."""
    if IP in pkt:
        payload_len = len(pkt[IP].payload) if Raw in pkt else 0
        # Normalize to 0-1 range (approximate)
        return min(payload_len / 1500.0, 1.0)
    return 0.0

def stream_pcap_packets(path: str, chunk_size: int = 10000) -> Iterator[List[float]]:
    """Stream packets from PCAP in chunks without loading entire file."""
    chunk = []
    for pkt in PcapReader(path):
        chunk.append(extract_packet_features(pkt))
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

def process_pcap_stream(
    path: str,
    chunk_size: int = 10000,
    overlap: int = 1000
) -> Dict[str, Any]:
    """Process large PCAP using streaming with overlap between chunks."""
    start_time = time.time()
    
    all_results = []
    total_packets = 0
    prev_tail = []
    
    for chunk in stream_pcap_packets(path, chunk_size):
        # Add overlap from previous chunk for continuity
        if prev_tail:
            chunk = prev_tail + chunk
        
        total_packets += len(chunk)
        
        # Run detection on chunk
        timestamps = list(range(len(chunk)))
        result = detect_fade(timestamps, chunk)
        
        if result["detected"]:
            result["packet_range"] = (total_packets - len(chunk), total_packets)
            all_results.append(result)
        
        # Save tail for overlap
        prev_tail = chunk[-overlap:] if len(chunk) > overlap else chunk
    
    elapsed = time.time() - start_time
    
    # Aggregate results
    if all_results:
        best = max(all_results, key=lambda r: r.get("score", 0))
        best["chunks_processed"] = total_packets // chunk_size + 1
        best["total_packets"] = total_packets
        best["processing_time_sec"] = round(elapsed, 3)
        best["throughput_pps"] = round(total_packets / elapsed, 0) if elapsed > 0 else 0
        return best
    
    return {
        "detected": False,
        "total_packets": total_packets,
        "processing_time_sec": round(elapsed, 3),
        "throughput_pps": round(total_packets / elapsed, 0) if elapsed > 0 else 0
    }

def benchmark_pcap_processing(path: str) -> Dict[str, Any]:
    """Benchmark PCAP processing with detailed metrics."""
    import os
    file_size_mb = os.path.getsize(path) / (1024 * 1024)
    
    result = process_pcap_stream(path)
    result["file_size_mb"] = round(file_size_mb, 2)
    result["mb_per_sec"] = round(file_size_mb / result["processing_time_sec"], 2) if result["processing_time_sec"] > 0 else 0
    
    return result
