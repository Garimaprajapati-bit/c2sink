"""The sinkhole server.

Accepts TCP connections redirected here for any feed destination, reads only
the first bytes the client sends, records metadata, and closes the connection
without ever sending application data back. It is deliberately passive: it
completes the TCP handshake (unavoidable, the kernel does it) and then stays
silent, so an infected device gets no commands from it.

Original destination recovery:
- Linux REDIRECT: SO_ORIGINAL_DST on the socket gives the real C2 address.
- Otherwise the local accept address is used (fine when the sink host holds
  the announced prefixes directly, e.g. via ExaBGP next-hop = this host).
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

from . import http as http_parser
from . import tls as tls_parser
from .feed import FeedIndex

SO_ORIGINAL_DST = 80          # <linux/netfilter_ipv4.h>
IP6T_SO_ORIGINAL_DST = 80     # <linux/netfilter_ipv6/ip6_tables.h>


@dataclass
class Event:
    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    bytes_from_client: int
    proto: str = "unknown"          # tls | http | unknown
    feed_label: Optional[str] = None
    sni: Optional[str] = None
    tls_version: Optional[int] = None
    ja3: Optional[str] = None
    alpn: list = field(default_factory=list)
    http_host: Optional[str] = None
    http_method: Optional[str] = None
    http_target: Optional[str] = None
    user_agent: Optional[str] = None
    first_bytes_hex: str = ""
    client_hello_complete: Optional[bool] = None

    def to_json_line(self) -> str:
        import json
        return json.dumps(asdict(self), separators=(",", ":"))


def _original_dst(sock: socket.socket) -> Optional[tuple]:
    try:
        family = sock.family
        if family == socket.AF_INET:
            raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port, = struct.unpack_from("!H", raw, 2)
            ip = socket.inet_ntop(socket.AF_INET, raw[4:8])
            return ip, port
        if family == socket.AF_INET6:
            raw = sock.getsockopt(41, IP6T_SO_ORIGINAL_DST, 28)  # 41 = IPPROTO_IPV6
            port, = struct.unpack_from("!H", raw, 2)
            ip = socket.inet_ntop(socket.AF_INET6, raw[8:24])
            return ip, port
    except (OSError, struct.error):
        return None
    return None


class Sinkhole:
    def __init__(self, feed_index: FeedIndex, on_event, read_bytes: int = 16384,
                 read_timeout: float = 5.0, linger_seconds: float = 0.0):
        self.feed = feed_index
        self.on_event = on_event
        self.read_bytes = read_bytes
        self.read_timeout = read_timeout
        self.linger_seconds = linger_seconds

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        sock = writer.get_extra_info("socket")
        local = writer.get_extra_info("sockname") or ("?", 0)
        dst = _original_dst(sock) if sock is not None else None
        if dst is None:
            dst = (local[0], local[1])
        data = b""
        try:
            data = await asyncio.wait_for(reader.read(self.read_bytes), timeout=self.read_timeout)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        event = self._build_event(peer, dst, data)
        try:
            self.on_event(event)
        finally:
            # Never write application data. Optionally hold the socket open a
            # moment so the client thinks it connected, then close.
            if self.linger_seconds:
                try:
                    await asyncio.sleep(self.linger_seconds)
                except asyncio.CancelledError:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, asyncio.TimeoutError):
                pass

    def _build_event(self, peer, dst, data: bytes) -> Event:
        entry = self.feed.lookup(dst[0])
        ev = Event(
            ts=time.time(), src_ip=peer[0], src_port=peer[1],
            dst_ip=dst[0], dst_port=dst[1], bytes_from_client=len(data),
            feed_label=entry.label if entry else None,
            first_bytes_hex=data[:32].hex(),
        )
        hello = tls_parser.parse_client_hello(data)
        if hello is not None:
            ev.proto = "tls"
            ev.sni = hello.sni
            ev.tls_version = hello.max_version
            ev.ja3 = hello.ja3
            ev.alpn = hello.alpn
            ev.client_hello_complete = hello.complete
            return ev
        req = http_parser.parse_request(data)
        if req is not None:
            ev.proto = "http"
            ev.http_host = req.host
            ev.http_method = req.method
            ev.http_target = req.target
            ev.user_agent = req.user_agent
        return ev

    async def serve(self, host: str, port: int) -> asyncio.base_events.Server:
        return await asyncio.start_server(self.handle, host, port, reuse_address=True)
