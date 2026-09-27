"""Streaming PCAP processor for large captures."""
import multiprocessing as mp
import os
import time
from pathlib import Path
import numpy as np
try:
    import resource
except ImportError:
    resource = None
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

def stream_pcap_packets(path: str, chunk_size: int = 10000, max_packets: int | None = None) -> Iterator[List[float]]:
    """Stream packets from PCAP in chunks without loading entire file."""
    chunk = []
    seen = 0
    for pkt in PcapReader(path):
        seen += 1
        if max_packets is not None and seen > max_packets:
            raise ValueError(f"PCAP exceeds {max_packets} packet limit")
        chunk.append(extract_packet_features(pkt))
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

def _process_pcap_stream_unsafe(
    path: str,
    chunk_size: int = 10000,
    overlap: int = 1000,
    max_packets: int = 1_000_000,
) -> Dict[str, Any]:
    """Process large PCAP using streaming with overlap between chunks."""
    start_time = time.time()
    
    all_results = []
    total_packets = 0
    prev_tail = []
    
    for chunk in stream_pcap_packets(path, chunk_size, max_packets=max_packets):
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


def _sandbox_worker(path: str, chunk_size: int, overlap: int, max_packets: int, cpu_seconds: int, address_space_bytes: int, output: mp.Queue) -> None:
    """Parse a hostile PCAP in a disposable worker with OS resource limits."""
    try:
        if resource is not None:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
            resource.setrlimit(resource.RLIMIT_AS, (address_space_bytes, address_space_bytes))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        output.put((True, _process_pcap_stream_unsafe(path, chunk_size, overlap, max_packets)))
    except BaseException as exc:
        output.put((False, f"{type(exc).__name__}: {exc}"))


def process_pcap_stream(
    path: str,
    chunk_size: int = 10000,
    overlap: int = 1000,
    *,
    max_packets: int | None = None,
    timeout_seconds: int | None = None,
    max_memory_mb: int | None = None,
) -> Dict[str, Any]:
    """Process a PCAP in an isolated worker with bounded CPU, memory and packet count."""
    file_path = Path(path)
    if not file_path.is_file():
        raise ValueError("PCAP path does not exist")
    max_bytes = int(os.getenv("THREATFADE_MAX_PCAP_BYTES", str(100 * 1024 * 1024)))
    if file_path.stat().st_size > max_bytes:
        raise ValueError(f"PCAP exceeds {max_bytes} byte limit")
    if not 100 <= chunk_size <= 100_000:
        raise ValueError("chunk_size out of bounds")
    if not 0 <= overlap < chunk_size:
        raise ValueError("overlap must be smaller than chunk_size")
    packet_limit = max_packets or int(os.getenv("THREATFADE_MAX_PCAP_PACKETS", "1000000"))
    timeout = timeout_seconds or int(os.getenv("THREATFADE_PCAP_TIMEOUT_SECONDS", "30"))
    memory_mb = max_memory_mb or int(os.getenv("THREATFADE_PCAP_MAX_MEMORY_MB", "512"))
    if packet_limit < 1 or timeout < 1 or memory_mb < 64:
        raise ValueError("invalid PCAP resource limits")
    output: mp.Queue = mp.Queue(maxsize=1)
    process = mp.Process(target=_sandbox_worker, args=(str(file_path), chunk_size, overlap, packet_limit, timeout, memory_mb * 1024 * 1024, output), daemon=True)
    process.start()
    process.join(timeout)
    if process.is_alive():
        process.kill()
        process.join(5)
        raise TimeoutError(f"PCAP processing exceeded {timeout}s limit")
    if output.empty():
        raise RuntimeError(f"PCAP worker exited without a result (exit={process.exitcode})")
    ok, payload = output.get()
    if not ok:
        raise RuntimeError(f"PCAP worker rejected capture: {payload}")
    return payload


def benchmark_pcap_processing(path: str) -> Dict[str, Any]:
    """Benchmark PCAP processing with detailed metrics."""
    import os
    file_size_mb = os.path.getsize(path) / (1024 * 1024)
    
    result = process_pcap_stream(path)
    result["file_size_mb"] = round(file_size_mb, 2)
    result["mb_per_sec"] = round(file_size_mb / result["processing_time_sec"], 2) if result["processing_time_sec"] > 0 else 0
    
    return result
