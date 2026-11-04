import struct

from c2sink.capture import ingest_pcap
from c2sink.dns import query_name
from c2sink.feed import FeedIndex, parse_feed
from c2sink.generate import (build_client_hello, build_http_get, dns_query,
                             tcp_segment, udp_datagram, write_pcap)
from c2sink.packet import parse_frame
from c2sink.quic import parse_initial
from c2sink import tzsp


def _write_mixed_pcap(path):
    ch = build_client_hello("c2.loader.example")
    http = build_http_get("panel.stealer.example", "/gate.php")
    quic = bytes([0xC0]) + struct.pack("!I", 1) + bytes([8]) + b"\x11\x22\x33\x44\x55\x66\x77\x88" + b"\x00" * 40
    t = 1000.0
    frames = [
        # TCP ClientHello split across two segments, with SYN + FIN
        (t, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1000, flags=0x02)),
        (t + .01, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1001, ch[:40])),
        (t + .02, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1001 + 40, ch[40:])),
        (t + .03, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1001 + len(ch), b"", flags=0x11)),
        # HTTP over TCP
        (t + 1, tcp_segment("100.64.0.12", "203.0.113.20", 44002, 80, 2000, flags=0x02)),
        (t + 1.01, tcp_segment("100.64.0.12", "203.0.113.20", 44002, 80, 2001, http)),
        (t + 1.02, tcp_segment("100.64.0.12", "203.0.113.20", 44002, 80, 2001 + len(http), b"", flags=0x11)),
        # UDP DNS and QUIC
        (t + 2, udp_datagram("100.64.0.13", "203.0.113.30", 51000, 53, dns_query("c2.bot.example"))),
        (t + 3, udp_datagram("100.64.0.9", "203.0.113.10", 44050, 443, quic)),
    ]
    write_pcap(path, frames)


def test_pcap_ingest_reassembles_and_parses_all_protocols(tmp_path):
    p = str(tmp_path / "mixed.pcap")
    _write_mixed_pcap(p)
    events = []
    n = ingest_pcap(p, FeedIndex(parse_feed(["203.0.113.0/24 Mixed"])), events.append)
    assert n == 9
    by = {(e.transport, e.proto): e for e in events}
    # split ClientHello was reassembled: SNI + a real JA4, marked complete
    tls = by[("tcp", "tls")]
    assert tls.sni == "c2.loader.example" and tls.client_hello_complete and tls.ja4
    assert by[("tcp", "http")].http_host == "panel.stealer.example"
    assert by[("udp", "dns")].dns_qname == "c2.bot.example"
    assert by[("udp", "quic")].quic_version == "0x00000001"


def test_dns_and_quic_parsers_reject_junk():
    assert query_name(b"not dns at all") is None
    assert query_name(dns_query("a.b.c")) == "a.b.c"
    assert parse_initial(b"\x00\x00") is None
    good = bytes([0xC0]) + struct.pack("!I", 1) + bytes([4]) + b"\xaa\xbb\xcc\xdd"
    assert parse_initial(good).version == 1


def test_tzsp_decapsulates_to_the_inner_frame():
    inner = udp_datagram("100.64.0.5", "203.0.113.9", 5000, 53, dns_query("x.example"))
    # TZSP: version 1, type 0 (received), encap 1 (Ethernet), END tag, then frame
    tzsp_pkt = bytes([1, 0]) + struct.pack("!H", 1) + bytes([tzsp.TZSP_TAG_END]) + inner
    decap = tzsp.decapsulate(tzsp_pkt)
    assert decap is not None
    linktype, frame = decap
    pkt = parse_frame(frame, linktype)
    assert pkt.transport == "udp" and pkt.dst_port == 53
    assert query_name(pkt.payload) == "x.example"
