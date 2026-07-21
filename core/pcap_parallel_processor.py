"""Parallel PCAP processor using multiprocessing for large captures."""
import os
import time
import numpy as np
from typing import List, Dict, Any, Tuple
from multiprocessing import Pool, cpu_count
from concurrent.futures import ProcessPoolExecutor, as_completed
from scapy.all import PcapReader, IP, TCP, UDP, Raw
from core.fade_engine import detect_fade


def extract_packet_features(pkt) -> float:
    """Extract a single feature value from a packet."""
    if IP in pkt:
        payload_len = len(pkt[IP].payload) if Raw in pkt else 0
        return min(payload_len / 1500.0, 1.0)
    return 0.0


def process_chunk(chunk_data: Tuple[int, List[float]]) -> Dict[str, Any]:
    """Process a single chunk of packets. Worker function for multiprocessing."""
    chunk_id, features = chunk_data
    if len(features) < 10:
        return {"chunk_id": chunk_id, "detected": False, "score": 0.0}

    timestamps = list(range(len(features)))
    result = detect_fade(timestamps, features)
    result["chunk_id"] = chunk_id
    result["packet_count"] = len(features)
    return result


def stream_pcap_to_chunks(path: str, chunk_size: int = 50000) -> List[Tuple[int, List[float]]]:
    """Stream PCAP into chunks ready for parallel processing."""
    chunks = []
    current_chunk = []
    chunk_id = 0

    for pkt in PcapReader(path):
        current_chunk.append(extract_packet_features(pkt))
        if len(current_chunk) >= chunk_size:
            chunks.append((chunk_id, current_chunk))
            chunk_id += 1
            current_chunk = []

    if current_chunk:
        chunks.append((chunk_id, current_chunk))

    return chunks


def process_pcap_parallel(
    path: str,
    chunk_size: int = 50000,
    max_workers: int = None
) -> Dict[str, Any]:
    """Process large PCAP using parallel chunk processing."""
    start_time = time.time()

    if max_workers is None:
        max_workers = min(cpu_count(), 8)

    print(f"[Parallel] Streaming PCAP into chunks (size={chunk_size})...")
    chunks = stream_pcap_to_chunks(path, chunk_size)
    total_packets = sum(len(c[1]) for c in chunks)

    print(f"[Parallel] Created {len(chunks)} chunks, {total_packets} total packets")
    print(f"[Parallel] Processing with {max_workers} workers...")

    results = []
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_chunk, chunk): chunk[0] for chunk in chunks}
        for future in as_completed(futures):
            chunk_id = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"[Parallel] Chunk {chunk_id} failed: {e}")

    elapsed = time.time() - start_time

    detected_chunks = [r for r in results if r.get("detected", False)]

    if detected_chunks:
        best = max(detected_chunks, key=lambda r: r.get("score", 0))
        best["chunks_processed"] = len(chunks)
        best["chunks_detected"] = len(detected_chunks)
        best["total_packets"] = total_packets
        best["processing_time_sec"] = round(elapsed, 3)
        best["throughput_pps"] = round(total_packets / elapsed, 0) if elapsed > 0 else 0
        best["parallel_workers"] = max_workers
        best["chunk_size"] = chunk_size
        return best

    return {
        "detected": False,
        "chunks_processed": len(chunks),
        "chunks_detected": 0,
        "total_packets": total_packets,
        "processing_time_sec": round(elapsed, 3),
        "throughput_pps": round(total_packets / elapsed, 0) if elapsed > 0 else 0,
        "parallel_workers": max_workers,
        "chunk_size": chunk_size
    }


def benchmark_parallel_vs_serial(path: str) -> Dict[str, Any]:
    """Benchmark parallel vs serial processing."""
    from core.pcap_stream_processor import process_pcap_stream

    print("\n=== SERIAL PROCESSING ===")
    serial_start = time.time()
    serial_result = process_pcap_stream(path)
    serial_time = time.time() - serial_start

    print("\n=== PARALLEL PROCESSING ===")
    parallel_start = time.time()
    parallel_result = process_pcap_parallel(path, max_workers=2)
    parallel_time = time.time() - parallel_start

    speedup = serial_time / parallel_time if parallel_time > 0 else 0

    return {
        "serial_time_sec": round(serial_time, 3),
        "parallel_time_sec": round(parallel_time, 3),
        "speedup": round(speedup, 2),
        "serial_result": serial_result,
        "parallel_result": parallel_result
    }
