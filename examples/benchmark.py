#!/usr/bin/env python3
"""Throughput / memory / event-loss benchmark under pathological traffic.

Feeds a mix of well-behaved and hostile flows straight through the reassembler
and the durable writer, then reports packets/sec, peak RSS and where events
went (written vs dropped vs timed out). The point is to show that resource use
stays bounded and loss is accounted for, not hidden.

    python examples/benchmark.py --flows 50000

Traffic mix per 'flow' unit:
  - 60% complete TLS flows (SYN, ClientHello, FIN)
  - 15% never-closing flows (SYN + partial data, no FIN  -> must time out)
  - 15% SYN-only scans (no data                          -> bounded, counted)
  - 10% retransmit storms (same segment many times       -> deduped, counted)
"""
import argparse
import os
import resource
import tempfile
import time

from c2sink.capture import Reassembler
from c2sink.feed import FeedIndex, parse_feed
from c2sink.generate import build_client_hello
from c2sink.metrics import Metrics
from c2sink.packet import Packet
from c2sink.writer import EventWriter

FEED = FeedIndex(parse_feed(["203.0.113.0/24 Bench"]))
CH = build_client_hello("bench.c2.example")


def pkt(sip, sport, seq, payload=b"", flags=0):
    return Packet(sip, "203.0.113.10", sport, 443, "tcp", payload, flags, seq)


def run(flows: int, max_queue: int = 10000) -> None:
    metrics = Metrics()
    tmp = tempfile.NamedTemporaryFile(prefix="c2sink-bench-", suffix=".jsonl", delete=False)
    tmp.close()
    writer = EventWriter(tmp.name, metrics=metrics, max_queue=max_queue)
    # short timeouts so never-closing flows expire within the run's virtual clock
    r = Reassembler(FEED, writer.submit_event, metrics=metrics,
                    idle_timeout=5.0, max_duration=20.0)

    t0 = time.time()
    vclock = 0.0
    packets = 0
    for i in range(flows):
        sip = "100.64.%d.%d" % ((i // 256) % 256, i % 256)
        sport = 1024 + (i % 60000)
        vclock += 0.001                      # advance the virtual capture clock
        kind = i % 20
        if kind < 12:                        # complete TLS
            r.feed_packet(vclock, pkt(sip, sport, 0, flags=0x02)); packets += 1
            r.feed_packet(vclock, pkt(sip, sport, 1, CH, 0x18)); packets += 1
            r.feed_packet(vclock, pkt(sip, sport, 1 + len(CH), b"", 0x11)); packets += 1
        elif kind < 15:                      # never-closing (partial, no FIN)
            r.feed_packet(vclock, pkt(sip, sport, 0, flags=0x02)); packets += 1
            r.feed_packet(vclock, pkt(sip, sport, 1, CH[:40], 0x18)); packets += 1
        elif kind < 18:                      # SYN-only scan
            r.feed_packet(vclock, pkt(sip, sport, 0, flags=0x02)); packets += 1
        else:                                # retransmit storm
            r.feed_packet(vclock, pkt(sip, sport, 0, flags=0x02)); packets += 1
            for _ in range(50):
                r.feed_packet(vclock, pkt(sip, sport, 1, CH, 0x18)); packets += 1
    r.finalize()
    writer.close()
    dt = time.time() - t0

    peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KiB on Linux
    s = metrics.snapshot()
    os.unlink(tmp.name)

    print(f"flows (units)        : {flows}")
    print(f"packets fed          : {packets}")
    print(f"wall time            : {dt:.2f}s")
    print(f"throughput           : {packets/dt:,.0f} packets/s")
    print(f"peak RSS             : {peak_kb/1024:.1f} MiB")
    print(f"events produced      : {s['events']}")
    print(f"events written       : {s['events_written']}")
    print(f"events dropped (full): {s['events_dropped']}")
    print(f"reassembly timeouts  : {s['reassembly_timeouts']}")
    print(f"segments deduped     : {s['segments_dropped']}")
    print(f"flows evicted (cap)  : {s['flows_evicted']}")
    print(f"active flows at end  : {s['active_flows']}")
    assert s["events_written"] + s["events_dropped"] == s["events"], "event accounting must balance"
    print("event accounting balances (written + dropped == produced)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=50000)
    ap.add_argument("--max-queue", type=int, default=10000)
    a = ap.parse_args()
    run(a.flows, a.max_queue)
