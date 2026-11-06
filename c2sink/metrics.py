"""Operational metrics for the collector itself.

This is distinct from the feed-health intelligence (which is about the traffic):
these counters answer "is c2sink healthy and keeping up?". They are plain ints,
rendered either as a short human summary or as Prometheus text. No external
dependencies and no dashboard -- a scrape endpoint or an end-of-run print is
enough, which is all an operator needs to see data loss or backpressure.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict

# Counters are cumulative; gauges (active_flows, queue_depth) are point-in-time.
_COUNTERS = (
    "packets", "events", "parse_failures", "reassembly_timeouts",
    "segments_dropped", "flows_evicted", "events_written", "events_dropped",
    "write_errors", "bytes_written",
)
_GAUGES = ("active_flows", "queue_depth")


@dataclass
class Metrics:
    start_time: float = field(default_factory=time.time)
    packets: int = 0                 # packets (capture) / connections (live sink) observed
    events: int = 0
    parse_failures: int = 0          # payload matched no known protocol
    reassembly_timeouts: int = 0     # flows flushed because they went idle / ran too long
    segments_dropped: int = 0        # retransmit / overlap / over per-flow cap
    flows_evicted: int = 0           # dropped because the flow table was full
    events_written: int = 0
    events_dropped: int = 0          # writer queue was full (backpressure, made visible)
    write_errors: int = 0            # e.g. disk full
    bytes_written: int = 0
    active_flows: int = 0            # gauge
    queue_depth: int = 0             # gauge
    by_proto: Dict[str, int] = field(default_factory=dict)

    def record_event(self, proto: str) -> None:
        self.events += 1
        self.by_proto[proto] = self.by_proto.get(proto, 0) + 1
        if proto == "unknown":
            self.parse_failures += 1

    @property
    def uptime(self) -> float:
        return time.time() - self.start_time

    def snapshot(self) -> Dict[str, float]:
        d = {k: getattr(self, k) for k in _COUNTERS + _GAUGES}
        d["uptime_seconds"] = round(self.uptime, 1)
        return d

    def render_text(self) -> str:
        lines = ["c2sink metrics", "=" * 32]
        for k, v in self.snapshot().items():
            lines.append(f"  {k:22} {v}")
        if self.by_proto:
            lines.append("  events by proto:")
            for p, n in sorted(self.by_proto.items()):
                lines.append(f"    {p:18} {n}")
        return "\n".join(lines)

    def render_prometheus(self) -> str:
        out = []
        for k, v in self.snapshot().items():
            out.append(f"c2sink_{k} {v}")
        for p, n in sorted(self.by_proto.items()):
            out.append(f'c2sink_events_by_proto{{proto="{p}"}} {n}')
        return "\n".join(out) + "\n"


async def serve_metrics(host: str, port: int, metrics: Metrics):
    """Minimal read-only HTTP endpoint: GET /metrics (Prometheus text) and
    GET /healthz. No framework; it parses the request line, discards headers,
    and returns one response. Returns the asyncio server."""
    import asyncio

    async def handle(reader, writer):
        try:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            except asyncio.TimeoutError:
                writer.close()
                return
            # drain headers up to the blank line, bounded
            for _ in range(64):
                h = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if h in (b"\r\n", b"\n", b""):
                    break
            path = (line.split(b" ")[1] if len(line.split(b" ")) > 1 else b"/").decode("latin-1")
            if path.startswith("/metrics"):
                body = metrics.render_prometheus().encode("utf-8")
                status, ctype = "200 OK", "text/plain; version=0.0.4"
            elif path.startswith("/healthz"):
                body, status, ctype = b"ok\n", "200 OK", "text/plain"
            else:
                body, status, ctype = b"not found\n", "404 Not Found", "text/plain"
            writer.write(
                f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("latin-1")
                + body)
            await writer.drain()
        except (ConnectionError, asyncio.TimeoutError, IndexError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(handle, host, port, reuse_address=True)
