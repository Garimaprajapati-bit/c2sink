"""Turn captured packets into events, independent of where they came from.

A pcap file, a live mirror, or a TZSP stream all produce the same `Event`
objects (via `analysis.build_event`) and therefore the same reports. This is
the point of the refactor: the analysis engine does not care how the traffic
was captured.

TCP is reassembled in the client->server direction so a ClientHello or HTTP
request split across segments is put back together. UDP is connectionless, so
the first datagram of each flow is taken as the contact. A capture that only
contains SYNs (a true blackhole with no responder) still produces one event
per attempted TCP flow, with no payload, which is the honest result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Tuple

from .analysis import Event, build_event
from .feed import FeedIndex
from .packet import Packet, parse_frame
from .pcap import read_pcap

Key = Tuple[str, int, str, int]


@dataclass
class _TcpFlow:
    first_ts: float
    isn: Optional[int] = None          # from the SYN; data starts at isn+1
    segments: Dict[int, bytes] = field(default_factory=dict)
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
                 max_bytes: int = 16384, max_flows: int = 4096, pseudonymizer=None):
        self.feed = feed_index
        self.on_event = on_event
        self.max_bytes = max_bytes
        self.max_flows = max_flows
        self.pseudonymizer = pseudonymizer
        self._tcp: Dict[Key, _TcpFlow] = {}
        self._udp_seen: set = set()

    def _new_flow(self, key: Key, ts: float) -> _TcpFlow:
        # Bound memory on a long-running live stream: a sinkhole sees far more
        # scans and half-open attempts than completed flows, so the flow table
        # would otherwise grow without limit. Once over the cap, drop the oldest
        # tracked flow (emitted ones carry the oldest timestamps, so they go
        # first) before adding the new one.
        if len(self._tcp) >= self.max_flows:
            oldest = min(self._tcp, key=lambda k: self._tcp[k].first_ts)
            self._tcp.pop(oldest, None)
        flow = _TcpFlow(first_ts=ts)
        self._tcp[key] = flow
        return flow

    def feed_packet(self, ts: float, pkt: Packet) -> None:
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
        if pkt.payload and not flow.emitted and len(flow.segments) < 64:
            flow.segments[pkt.seq] = pkt.payload
        if pkt.tcp_flags & 0x05 and not flow.emitted:   # FIN or RST
            flow.closed = True
            self._flush_tcp(fwd)

    def _flush_tcp(self, key: Key) -> None:
        flow = self._tcp.get(key)
        if flow is None or flow.emitted:
            return
        flow.emitted = True
        payload = flow.reassemble(self.max_bytes)
        flow.segments = {}                           # free the buffered bytes; keep a
        #                                              small tombstone so a post-close
        #                                              retransmit isn't re-emitted.
        src_ip, src_port, dst_ip, dst_port = key
        self._emit(flow.first_ts, src_ip, src_port, dst_ip, dst_port, payload, "tcp")

    def _emit(self, ts, src_ip, src_port, dst_ip, dst_port, payload, transport) -> None:
        ev = build_event(ts, src_ip, src_port, dst_ip, dst_port, payload,
                         self.feed, transport=transport, pseudonymizer=self.pseudonymizer)
        self.on_event(ev)

    def finalize(self) -> None:
        for key in list(self._tcp):
            self._flush_tcp(key)


def ingest_pcap(path: str, feed_index: FeedIndex, on_event: Callable[[Event], None],
                max_bytes: int = 16384, pseudonymizer=None) -> int:
    """Replay a pcap through the reassembler. Returns the packet count read."""
    r = Reassembler(feed_index, on_event, max_bytes, pseudonymizer=pseudonymizer)
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
                     pseudonymizer=None):
    """Listen for TZSP-encapsulated packets over UDP and feed them to the same
    reassembler as a pcap. Returns the asyncio transport; call finalize() on the
    protocol's reassembler to flush open TCP flows."""
    import asyncio
    import time

    from . import tzsp
    from .packet import parse_frame as _parse

    r = Reassembler(feed_index, on_event, max_bytes, pseudonymizer=pseudonymizer)

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
    return transport, r
