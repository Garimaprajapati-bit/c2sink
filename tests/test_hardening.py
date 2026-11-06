"""Edge-case and robustness tests.

The parsers read attacker-controlled bytes (this is malware traffic), so the
contract is: never raise on garbage, never read out of bounds, and parse real
on-the-wire framing correctly -- including the awkward bits (link-layer padding,
truncation, IPv6 extension headers, segment reassembly).
"""

import os
import random
import struct

import pytest

from c2sink import tzsp
from c2sink.analysis import build_event
from c2sink.capture import Reassembler, ingest_pcap
from c2sink.dns import query_name
from c2sink.feed import FeedIndex, parse_feed
from c2sink.generate import (build_client_hello, build_http_get, dns_query,
                             tcp_segment, udp_datagram, write_pcap, _ipv4)
from c2sink.http import parse_request
from c2sink.packet import Packet, parse_frame
from c2sink.quic import parse_initial
from c2sink.tls import parse_client_hello

ETH = b"\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00"
FEED = FeedIndex(parse_feed(["203.0.113.0/24 Test", "2001:db8:bad::/48 Test6"]))


# --- fuzzing: no parser may raise on arbitrary bytes ----------------------

def test_parsers_never_raise_on_random_bytes():
    rnd = random.Random(1337)
    for _ in range(4000):
        n = rnd.randint(0, 80)
        blob = bytes(rnd.randrange(256) for _ in range(n))
        # every entry point must return None or a value, never raise
        assert parse_client_hello(blob) is None or parse_client_hello(blob) is not None
        parse_request(blob)
        query_name(blob)
        parse_initial(blob)
        tzsp.decapsulate(blob)
        for lt in (1, 101, 113, 0, 999):
            parse_frame(blob, lt)


def test_build_event_never_raises_on_random_payload():
    rnd = random.Random(42)
    for _ in range(2000):
        blob = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 64)))
        for transport in ("tcp", "udp"):
            ev = build_event(1.0, "100.64.0.1", 5000, "203.0.113.9", 443,
                             blob, FEED, transport=transport)
            ev.to_json_line()      # must serialise cleanly too


# --- link-layer padding must not leak into the payload --------------------

def test_ethernet_padding_is_stripped_from_udp():
    # a real NIC pads this sub-60-byte frame with zeros; they must be dropped
    payload = dns_query("c2.bot.example")
    frame = udp_datagram("100.64.0.5", "203.0.113.9", 5000, 53, payload)
    padded = frame + b"\x00" * 24
    pkt = parse_frame(padded, 1)
    assert pkt.transport == "udp"
    assert pkt.payload == payload              # exactly, no trailing padding
    assert query_name(pkt.payload) == "c2.bot.example"
    ev = build_event(1.0, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
                     pkt.payload, FEED, transport="udp")
    assert ev.bytes_from_client == len(payload)   # count is honest


def test_ethernet_padding_is_stripped_from_tcp():
    seg = tcp_segment("100.64.0.5", "203.0.113.9", 4444, 80, 1000,
                      build_http_get("panel.example", "/x"), flags=0x18)
    pkt = parse_frame(seg + b"\x00" * 30, 1)
    assert pkt.transport == "tcp"
    assert pkt.payload == build_http_get("panel.example", "/x")


def test_bare_syn_has_no_payload_despite_padding():
    syn = tcp_segment("100.64.0.5", "203.0.113.9", 4444, 443, 1000, b"", flags=0x02)
    pkt = parse_frame(syn + b"\x00" * 26, 1)
    assert pkt.syn and pkt.payload == b""


# --- IPv6, including an extension header -----------------------------------

def _ipv6(src, dst, nexthdr, payload):
    import socket
    s = socket.inet_pton(socket.AF_INET6, src)
    d = socket.inet_pton(socket.AF_INET6, dst)
    # version(6) + traffic class/flow label, payload length, next header, hop limit
    hdr = struct.pack("!IHBB", 0x60000000, len(payload), nexthdr, 64) + s + d
    return ETH[:12] + b"\x86\xdd" + hdr + payload


def test_ipv6_tcp_is_parsed():
    tcp = struct.pack("!HHIIBBHHH", 5000, 443, 1000, 0, 0x50, 0x02, 65535, 0, 0)
    frame = _ipv6("2001:db8:bad::1", "2001:db8:bad::99", 6, tcp)
    pkt = parse_frame(frame, 1)
    assert pkt is not None and pkt.transport == "tcp" and pkt.dst_port == 443
    assert pkt.dst_ip == "2001:db8:bad::99"


def test_ipv6_hop_by_hop_extension_is_skipped():
    tcp = struct.pack("!HHIIBBHHH", 5000, 443, 1000, 0, 0x50, 0x02, 65535, 0, 0)
    # one 8-byte hop-by-hop header (next=TCP, hdr-ext-len=0) before the TCP header
    ext = struct.pack("!BB", 6, 0) + b"\x00" * 6
    frame = _ipv6("2001:db8:bad::1", "2001:db8:bad::99", 0, ext + tcp)
    pkt = parse_frame(frame, 1)
    assert pkt is not None and pkt.transport == "tcp" and pkt.dst_port == 443


# --- truncation is data, not a crash --------------------------------------

def test_truncated_client_hello_is_flagged_not_dropped():
    full = build_client_hello("split.example.com")
    for cut in range(6, len(full)):
        h = parse_client_hello(full[:cut])
        assert h is not None                 # recognised as TLS
        if cut < len(full):
            assert h.complete is False
    assert parse_client_hello(full).complete is True
    assert parse_client_hello(full).sni == "split.example.com"


def test_tls_with_declared_but_absent_ciphers():
    # claim a huge cipher list the record doesn't contain
    data = bytes([0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x40,
                  0x03, 0x03]) + b"\x00" * 32 + b"\x00" + b"\xff\xfe"
    h = parse_client_hello(data)
    assert h is not None and h.complete is False


# --- reassembly edge cases -------------------------------------------------

def test_out_of_order_segments_are_reassembled():
    ch = build_client_hello("ooo.example")
    a, b, c = ch[:20], ch[20:50], ch[50:]
    frames = [
        (1.0, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1000, flags=0x02)),
        (1.03, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1001 + 50, c)),
        (1.01, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1001, a)),
        (1.02, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1001 + 20, b)),
        (1.04, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1001 + len(ch), b"", flags=0x11)),
    ]
    p = "/tmp/claude-0/ooo.pcap"
    os.makedirs(os.path.dirname(p), exist_ok=True)
    write_pcap(p, frames)
    events = []
    ingest_pcap(p, FEED, events.append)
    tls = [e for e in events if e.proto == "tls"]
    assert len(tls) == 1 and tls[0].sni == "ooo.example" and tls[0].client_hello_complete


def test_retransmit_after_close_does_not_double_emit():
    http = build_http_get("re.example", "/")
    frames = [
        (1.0, tcp_segment("100.64.0.9", "203.0.113.10", 44002, 80, 2000, flags=0x02)),
        (1.01, tcp_segment("100.64.0.9", "203.0.113.10", 44002, 80, 2001, http)),
        (1.02, tcp_segment("100.64.0.9", "203.0.113.10", 44002, 80, 2001 + len(http), b"", flags=0x11)),
        # duplicate data + a lone ACK arriving after the FIN
        (1.03, tcp_segment("100.64.0.9", "203.0.113.10", 44002, 80, 2001, http)),
        (1.04, tcp_segment("100.64.0.9", "203.0.113.10", 44002, 80, 3000, b"", flags=0x10)),
    ]
    p = "/tmp/claude-0/re.pcap"
    os.makedirs(os.path.dirname(p), exist_ok=True)
    write_pcap(p, frames)
    events = []
    ingest_pcap(p, FEED, events.append)
    http_events = [e for e in events if e.proto == "http"]
    assert len(http_events) == 1        # exactly one, no spurious empty re-emit


def test_flow_table_is_bounded():
    r = Reassembler(FEED, lambda ev: None, max_flows=100)
    for i in range(1000):
        syn = Packet("10.0.%d.%d" % (i // 256, i % 256), 40000 + i,
                     "203.0.113.10", 443, "tcp", b"", tcp_flags=0x02, seq=i)
        r.feed_packet(float(i), syn)
    assert len(r._tcp) <= 100


def test_udp_dedup_set_is_bounded():
    r = Reassembler(FEED, lambda ev: None, max_flows=10)
    for i in range(1000):
        u = Packet("10.0.%d.%d" % (i // 256, i % 256), 5000,
                   "203.0.113.10", 53, "udp", dns_query("x.example"))
        r.feed_packet(float(i), u)
    assert len(r._udp_seen) <= 10 * 8


# --- TZSP decapsulation round-trip and junk rejection ----------------------

def test_tzsp_roundtrip_and_rejects_junk():
    inner = udp_datagram("100.64.0.5", "203.0.113.9", 5000, 53, dns_query("x.example"))
    pkt = bytes([1, 0]) + struct.pack("!H", 1) + bytes([tzsp.TZSP_TAG_END]) + inner
    lt, frame = tzsp.decapsulate(pkt)
    assert parse_frame(frame, lt).dst_port == 53
    assert tzsp.decapsulate(b"\x00") is None
    assert tzsp.decapsulate(b"\x02\x00\x00\x01") is None     # wrong version


# --- pcap reader robustness ------------------------------------------------

def test_pcap_reader_rejects_non_pcap(tmp_path):
    p = tmp_path / "junk.bin"
    p.write_bytes(b"this is not a pcap file at all, really")
    with pytest.raises(ValueError):
        list(__import__("c2sink.pcap", fromlist=["read_pcap"]).read_pcap(str(p)))


def test_pcap_reader_stops_on_truncated_record(tmp_path):
    good = udp_datagram("100.64.0.5", "203.0.113.9", 5000, 53, dns_query("a.b"))
    p = str(tmp_path / "trunc.pcap")
    write_pcap(p, [(1.0, good)])
    # append a record header that claims more bytes than follow
    with open(p, "ab") as fh:
        fh.write(struct.pack("<IIII", 2, 0, 9999, 9999) + b"\x01\x02\x03")
    events = []
    n = ingest_pcap(p, FEED, events.append)
    assert n == 1 and events[0].dns_qname == "a.b"     # first packet survives, no crash
