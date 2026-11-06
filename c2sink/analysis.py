"""Analysis layer: turn one captured first-payload into an Event.

This is independent of how the payload was captured. The live sink
(`server.py`) and the offline/packet capture path (`capture.py`) both call
`build_event`, so pcap replay and live traffic produce identical events and
feed the same reports.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Optional

from . import dns as dns_parser
from . import http as http_parser
from . import quic as quic_parser
from . import tls as tls_parser
from .feed import FeedIndex


@dataclass
class Event:
    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    bytes_from_client: int
    transport: str = "tcp"          # tcp | udp
    proto: str = "unknown"          # tls | http | dns | quic | unknown
    feed_label: Optional[str] = None
    sni: Optional[str] = None
    tls_version: Optional[int] = None
    ja3: Optional[str] = None
    ja4: Optional[str] = None
    alpn: list = field(default_factory=list)
    http_host: Optional[str] = None
    http_method: Optional[str] = None
    http_target: Optional[str] = None
    user_agent: Optional[str] = None
    dns_qname: Optional[str] = None
    quic_version: Optional[str] = None
    first_bytes_hex: str = ""
    client_hello_complete: Optional[bool] = None

    def to_json_line(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))


def build_event(ts: float, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                payload: bytes, feed_index: FeedIndex, transport: str = "tcp",
                pseudonymizer=None) -> Event:
    entry = feed_index.lookup(dst_ip)
    # The destination is the C2 (threat intel); keep it clear. The source is
    # one of the operator's own subscribers, so pseudonymise it when asked,
    # before it is ever written to the log.
    if pseudonymizer is not None:
        src_ip = pseudonymizer.ip(src_ip)
    ev = Event(
        ts=ts, src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
        bytes_from_client=len(payload), transport=transport,
        feed_label=entry.label if entry else None,
        first_bytes_hex=payload[:32].hex(),
    )

    hello = tls_parser.parse_client_hello(payload)
    if hello is not None:
        ev.proto = "tls"
        ev.sni = hello.sni
        ev.tls_version = hello.max_version
        ev.ja3 = hello.ja3
        ev.ja4 = hello.ja4
        ev.alpn = hello.alpn
        ev.client_hello_complete = hello.complete
        return ev

    req = http_parser.parse_request(payload)
    if req is not None:
        ev.proto = "http"
        ev.http_host = req.host
        ev.http_method = req.method
        ev.http_target = req.target
        ev.user_agent = req.user_agent
        return ev

    if transport == "udp":
        quic = quic_parser.parse_initial(payload)
        if quic is not None:
            ev.proto = "quic"
            ev.quic_version = f"0x{quic.version:08x}"
            return ev
        qname = dns_parser.query_name(payload)
        if qname is not None:
            ev.proto = "dns"
            ev.dns_qname = qname
            return ev

    return ev
