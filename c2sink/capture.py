"""Turn captured packets into events, independent of where they came from.

A pcap file, a live mirror, or a TZSP stream all produce the same `Event`
objects (via `analysis.build_event`) and therefore the same reports. This is
the point of the refactor: the analysis engine does not care how the traffic
was captured.

TCP is reassembled in the client->server direction so a ClientHello or HTTP
request split across segments is put back together. UDP is connectionless, so
the first datagram of each flow is taken as the contact.

Reassembly is **bounded** so hostile traffic cannot exhaust memory:

- at most `max_bytes` buffered per flow and at most 64 segments;
- at most `max_flows` concurrent flows (the oldest is evicted over the cap);
- a flow idle for `idle_timeout`, or open longer than `max_duration`, is flushed
  (emitting whatever was captured) and dropped;
- overlapping/retransmitted segments are resolved first-writer-wins, so a later
  packet cannot overwrite earlier data (an anti-evasion and anti-corruption
  choice);
- buffers are freed on FIN/RST and on timeout.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Tuple

from .analysis import Event, build_event
from .feed import FeedIndex
from .metrics import Metrics
from .packet import Packet, parse_frame
from .pcap import read_pcap

Key = Tuple[str, int, str, int]

MAX_SEGMENTS = 64


@dataclass
class _TcpFlow:
    first_ts: float
    last_ts: float
    isn: Optional[int] = None          # from the SYN; data starts at isn+1
    segments: Dict[int, bytes] = field(default_factory=dict)
    buffered: int = 0                  # total bytes held, to bound memory
    closed: bool = False
    emitted: bool = False

    def reassemble(self, max_bytes: int) -> bytes:
        if not self.segments:
            return b""
        base = (self.isn + 1) & 0xFFFFFFFF if self.isn is not None else min(self.segments)
        out = bytearray()
        seq = base
        while seq in self.segments and len(out) < max_bytes:
            chunk = self.segments.pop(seq)
            out += chunk
            seq = (seq + len(chunk)) & 0xFFFFFFFF
        return bytes(out[:max_bytes])


class Reassembler:
    def __init__(self, feed_index: FeedIndex, on_event: Callable[[Event], None],
                 max_bytes: int = 16384, max_flows: int = 4096,
                 idle_timeout: float = 60.0, max_duration: float = 300.0,
                 pseudonymizer=None, metrics: Metrics = None):
        self.feed = feed_index
        self.on_event = on_event
        self.max_bytes = max_bytes
        self.max_flows = max_flows
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        self.pseudonymizer = pseudonymizer
        self.metrics = metrics or Metrics()
        self._tcp: Dict[Key, _TcpFlow] = {}
        self._udp_seen: set = set()
        self._last_expire: Optional[float] = None

    def _new_flow(self, key: Key, ts: float) -> _TcpFlow:
        # Bound memory on a long-running stream: a sinkhole sees far more scans
        # and half-open attempts than completed flows. Over the cap, drop the
        # oldest-inserted flow before adding the new one. dict preserves
        # insertion order, so this is O(1) (no scan) -- important when the table
        # churns under a flood of short-lived connections.
        if len(self._tcp) >= self.max_flows:
            self._tcp.pop(next(iter(self._tcp)), None)
            self.metrics.flows_evicted += 1
        flow = _TcpFlow(first_ts=ts, last_ts=ts)
        self._tcp[key] = flow
        return flow

    def feed_packet(self, ts: float, pkt: Packet) -> None:
        self.metrics.packets += 1
        # Run an expiry sweep at most twice per idle window, so it is cheap even
        # under heavy traffic (driven by the capture's own timestamps).
        if self._last_expire is None:
            self._last_expire = ts
        elif ts - self._last_expire >= max(self.idle_timeout / 2.0, 1.0):
            self.expire(ts)
            self._last_expire = ts

        if pkt.transport == "udp":
            key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
            if key in self._udp_seen:
                return
            if len(self._udp_seen) >= self.max_flows * 8:
                self._udp_seen.clear()               # reset dedup, don't grow forever
            self._udp_seen.add(key)
            self._emit(ts, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
                       pkt.payload, "udp")
            return

        fwd = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        rev = (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)
        if pkt.syn and not (pkt.tcp_flags & 0x10):   # SYN without ACK -> client side
            flow = self._tcp.get(fwd) or self._new_flow(fwd, ts)
            flow.isn = pkt.seq
            flow.last_ts = ts
            return
        if fwd in self._tcp:
            flow = self._tcp[fwd]
        elif rev in self._tcp:
            return                                   # server->client, ignore
        else:
            # no SYN seen; treat traffic toward a listed prefix as client->server
            if self.feed.lookup(pkt.dst_ip) is None:
                return
            flow = self._new_flow(fwd, ts)
        flow.last_ts = ts
        if pkt.payload and not flow.emitted:
            # First-writer-wins: ignore a segment whose sequence we already hold
            # (retransmit/overlap) and anything past the per-flow byte or segment
            # cap. This bounds memory to max_flows * max_bytes and stops a later
            # packet overwriting earlier data.
            if (pkt.seq not in flow.segments and flow.buffered < self.max_bytes
                    and len(flow.segments) < MAX_SEGMENTS):
                flow.segments[pkt.seq] = pkt.payload
                flow.buffered += len(pkt.payload)
            else:
                self.metrics.segments_dropped += 1
        if pkt.tcp_flags & 0x05 and not flow.emitted:   # FIN or RST
            flow.closed = True
            self._flush_tcp(fwd)

    def _flush_tcp(self, key: Key) -> None:
        flow = self._tcp.get(key)
        if flow is None or flow.emitted:
            return
        flow.emitted = True
        payload = flow.reassemble(self.max_bytes)
        flow.segments = {}                           # free buffered bytes; keep a
        flow.buffered = 0                            # small tombstone against re-emit
        src_ip, src_port, dst_ip, dst_port = key
        self._emit(flow.first_ts, src_ip, src_port, dst_ip, dst_port, payload, "tcp")

    def expire(self, now: float) -> None:
        """Flush flows that went idle or have been open too long, and reap
        emitted tombstones once they too are idle. Keeps the flow table bounded
        in time, not just in count."""
        for key in list(self._tcp):
            flow = self._tcp.get(key)
            if flow is None:
                continue
            if flow.emitted:
                if now - flow.last_ts >= self.idle_timeout:
                    self._tcp.pop(key, None)
                continue
            if (now - flow.last_ts >= self.idle_timeout
                    or now - flow.first_ts >= self.max_duration):
                self.metrics.reassembly_timeouts += 1
                self._flush_tcp(key)                 # emit the honest partial
                self._tcp.pop(key, None)
        self.metrics.active_flows = len(self._tcp)

    def _emit(self, ts, src_ip, src_port, dst_ip, dst_port, payload, transport) -> None:
        ev = build_event(ts, src_ip, src_port, dst_ip, dst_port, payload,
                         self.feed, transport=transport, pseudonymizer=self.pseudonymizer)
        self.metrics.record_event(ev.proto)
        self.on_event(ev)

    def finalize(self) -> None:
        for key in list(self._tcp):
            self._flush_tcp(key)
        self._tcp.clear()
        self.metrics.active_flows = 0


def ingest_pcap(path: str, feed_index: FeedIndex, on_event: Callable[[Event], None],
                max_bytes: int = 16384, pseudonymizer=None, metrics: Metrics = None,
                **flow_opts) -> int:
    """Replay a pcap through the reassembler. Returns the packet count read.
    `flow_opts` (max_flows, idle_timeout, max_duration) are passed through."""
    r = Reassembler(feed_index, on_event, max_bytes, pseudonymizer=pseudonymizer,
                    metrics=metrics, **flow_opts)
    n = 0
    for ts, linktype, frame in read_pcap(path):
        n += 1
        pkt = parse_frame(frame, linktype)
        if pkt is not None:
            r.feed_packet(ts, pkt)
    r.finalize()
    return n


async def serve_tzsp(host: str, port: int, feed_index: FeedIndex,
                     on_event: Callable[[Event], None], max_bytes: int = 16384,
                     pseudonymizer=None, metrics: Metrics = None, **flow_opts):
    """Listen for TZSP-encapsulated packets over UDP and feed them to the same
    reassembler as a pcap. Returns (transport, reassembler); call finalize() on
    the reassembler to flush open TCP flows. A periodic task runs expiry so idle
    flows are flushed even without new traffic."""
    import asyncio
    import time

    from . import tzsp
    from .packet import parse_frame as _parse

    r = Reassembler(feed_index, on_event, max_bytes, pseudonymizer=pseudonymizer,
                    metrics=metrics, **flow_opts)

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            decap = tzsp.decapsulate(data)
            if decap is None:
                return
            linktype, frame = decap
            pkt = _parse(frame, linktype)
            if pkt is not None:
                r.feed_packet(time.time(), pkt)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(_Proto, local_addr=(host, port))

    async def _expiry():
        while True:
            await asyncio.sleep(max(r.idle_timeout / 2.0, 1.0))
            r.expire(time.time())

    r._expiry_task = loop.create_task(_expiry())   # cancelled by the caller on shutdown
    return transport, r
