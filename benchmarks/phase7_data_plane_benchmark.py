"""Reproducible Phase 7 data-plane benchmark."""
from __future__ import annotations
import argparse, gc, json, os, platform, statistics, time
from core.data_plane import BoundedEventQueue, new_event

def run(rate: int, duration: float) -> dict:
    total=max(1,int(rate*duration)); q=BoundedEventQueue(maxsize=min(max(total,4096),1_000_000))
    lat=[]; accepted=dropped=0; gc.disable(); start=time.perf_counter_ns()
    for _ in range(total):
        t=time.perf_counter_ns(); e=new_event("bench-sensor","bench-tenant","packet",protocol="tcp",packets=1)
        if q.put(e): accepted+=1
        else: dropped+=1
        lat.append(time.perf_counter_ns()-t)
    elapsed=(time.perf_counter_ns()-start)/1e9; gc.enable(); m=q.metrics(); s=sorted(lat)
    return {"requested_events":total,"duration_seconds":duration,"elapsed_seconds":elapsed,"throughput_events_per_second":total/elapsed,"accepted":accepted,"dropped":dropped,"drop_rate":dropped/total,"queue_depth":m["depth"],"latency_us_p50":statistics.median(lat)/1000,"latency_us_p99":s[max(0,int(len(s)*.99)-1)]/1000,"python":platform.python_version(),"platform":platform.platform(),"cpu_count":os.cpu_count()}

def main():
    p=argparse.ArgumentParser(); p.add_argument("--rate",type=int,default=10_000); p.add_argument("--duration",type=float,default=10.0); a=p.parse_args(); print(json.dumps(run(a.rate,a.duration),indent=2,sort_keys=True))
if __name__=="__main__": main()
