"""Production-hardening tests: bounded reassembly, durable writing, and the
capture-path equivalence the architecture claims.
"""

import json
import struct
import time

import pytest

from c2sink import tzsp
from c2sink.capture import Reassembler, ingest_pcap
from c2sink.feed import FeedIndex, parse_feed
from c2sink.generate import (build_client_hello, build_http_get, send,
                             tcp_segment, udp_datagram, dns_query, write_pcap)
from c2sink.metrics import Metrics
from c2sink.packet import Packet, parse_frame
from c2sink.report import load_events
from c2sink.server import Sinkhole
from c2sink.writer import EventWriter

FEED = FeedIndex(parse_feed(["203.0.113.0/24 Test", "127.0.0.1/32 Test", "::1/128 Test"]))

# flow key is (src_ip, src_port, dst_ip, dst_port); Packet's constructor order
# is (src_ip, dst_ip, src_port, dst_port, ...). Build via the client 5-tuple:
def _pkt(src_ip, src_port, dst_ip, dst_port, payload=b"", flags=0, seq=0):
    return Packet(src_ip, dst_ip, src_port, dst_port, "tcp", payload, flags, seq)


def _key(src_ip, src_port, dst_ip, dst_port):
    return (src_ip, src_port, dst_ip, dst_port)


# --- A. bounded reassembly -------------------------------------------------

def test_per_flow_byte_cap_bounds_memory():
    # a flow that keeps sending data must never buffer more than ~max_bytes
    r = Reassembler(FEED, lambda ev: None, max_bytes=1000)
    r.feed_packet(0.0, _pkt("100.64.0.1", 5000, "203.0.113.10", 443, flags=0x02, seq=0))
    seq = 1
    for _ in range(100):
        r.feed_packet(0.0, _pkt("100.64.0.1", 5000, "203.0.113.10", 443, b"A" * 500, 0x18, seq))
        seq += 500
    flow = r._tcp[_key("100.64.0.1", 5000, "203.0.113.10", 443)]
    assert flow.buffered <= 1000 + 500       # never unbounded
    assert r.metrics.segments_dropped > 0


def test_overlapping_segment_does_not_overwrite_earlier_data():
    r = Reassembler(FEED, lambda ev: None)
    k = _key("100.64.0.1", 5000, "203.0.113.10", 443)
    r.feed_packet(0.0, _pkt("100.64.0.1", 5000, "203.0.113.10", 443, flags=0x02, seq=0))
    r.feed_packet(0.0, _pkt("100.64.0.1", 5000, "203.0.113.10", 443, b"FIRST", 0x18, 1))
    r.feed_packet(0.0, _pkt("100.64.0.1", 5000, "203.0.113.10", 443, b"EVIL!", 0x18, 1))  # same seq
    assert r._tcp[k].segments[1] == b"FIRST"     # first-writer-wins
    assert r.metrics.segments_dropped == 1


def test_idle_timeout_flushes_and_frees_the_flow():
    events = []
    r = Reassembler(FEED, events.append, idle_timeout=10.0, max_duration=1000.0)
    k = _key("100.64.0.1", 5000, "203.0.113.10", 443)
    r.feed_packet(0.0, _pkt("100.64.0.1", 5000, "203.0.113.10", 443, flags=0x02, seq=0))
    r.feed_packet(0.0, _pkt("100.64.0.1", 5000, "203.0.113.10", 443, build_client_hello("c2.example"), 0x18, 1))
    r.expire(100.0)                               # long after idle_timeout
    assert k not in r._tcp                         # freed
    assert len(events) == 1 and events[0].sni == "c2.example"
    assert r.metrics.reassembly_timeouts == 1


def test_max_duration_flushes_a_never_closing_flow():
    events = []
    r = Reassembler(FEED, events.append, idle_timeout=1e9, max_duration=30.0)
    k = _key("100.64.0.1", 5000, "203.0.113.10", 443)
    r.feed_packet(0.0, _pkt("100.64.0.1", 5000, "203.0.113.10", 443, flags=0x02, seq=0))
    r.feed_packet(0.0, _pkt("100.64.0.1", 5000, "203.0.113.10", 443, build_http_get("h.example"), 0x18, 1))
    r.feed_packet(100.0, _pkt("100.64.0.1", 5000, "203.0.113.10", 443, b"x", 0x18, 9999))  # still "active"
    r.expire(100.0)
    assert k not in r._tcp and len(events) == 1


def test_flow_table_is_bounded_and_counts_evictions():
    # constant timestamp + huge timeouts so the *count* cap (not expiry) is what bounds it
    r = Reassembler(FEED, lambda ev: None, max_flows=100, idle_timeout=1e9, max_duration=1e9)
    for i in range(1000):
        r.feed_packet(0.0, _pkt("10.0.%d.%d" % (i // 256, i % 256), 40000 + i,
                                "203.0.113.10", 443, flags=0x02, seq=i))
    assert len(r._tcp) <= 100 and r.metrics.flows_evicted > 0


# --- B. durable, bounded writing -------------------------------------------

def test_writer_persists_and_counts(tmp_path):
    m = Metrics()
    w = EventWriter(str(tmp_path / "e.jsonl"), metrics=m, flush_interval=0.05)
    for i in range(50):
        w.submit(json.dumps({"i": i}))
    w.close()
    lines = [l for l in open(tmp_path / "e.jsonl") if l.strip()]
    assert len(lines) == 50 and m.events_written == 50 and m.events_dropped == 0


def test_writer_drops_and_counts_when_queue_full(tmp_path):
    # a tiny queue with the drain thread paused: overflow must be dropped+counted,
    # never block the caller
    m = Metrics()
    w = EventWriter(str(tmp_path / "e.jsonl"), metrics=m, max_queue=5)
    w._stop.set()                                  # freeze the drain loop
    w._thread.join(timeout=2.0)
    accepted = sum(w.submit("x") for _ in range(100))
    assert accepted <= 5 and m.events_dropped >= 95   # backpressure is visible
    w.close()


def test_writer_close_is_idempotent_and_flushes(tmp_path):
    p = str(tmp_path / "e.jsonl")
    with EventWriter(p) as w:
        w.submit('{"a":1}')
    assert json.loads(open(p).read().strip()) == {"a": 1}


def test_loader_tolerates_a_partial_final_line(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text('{"src_ip":"1.1.1.1","ts":1}\n{"src_ip":"2.2.2.2","ts":2}\n{"src_ip":"3.3.3')
    events = load_events(str(p))                   # last line is a torn write
    assert len(events) == 2                         # the two good lines survive


# --- E. capture-path equivalence -------------------------------------------

def _mixed_frames():
    ch = build_client_hello("same.example")
    http = build_http_get("host.example", "/g")
    t = 1000.0
    return [
        (t, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1000, flags=0x02)),
        (t + .01, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1001, ch)),
        (t + .02, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1001 + len(ch), b"", flags=0x11)),
        (t + 1, tcp_segment("100.64.0.12", "203.0.113.20", 44002, 80, 2000, flags=0x02)),
        (t + 1.01, tcp_segment("100.64.0.12", "203.0.113.20", 44002, 80, 2001, http)),
        (t + 1.02, tcp_segment("100.64.0.12", "203.0.113.20", 44002, 80, 2001 + len(http), b"", flags=0x11)),
        (t + 2, udp_datagram("100.64.0.13", "203.0.113.30", 51000, 53, dns_query("c2.bot.example"))),
    ]


def _fields(ev):
    return (ev.transport, ev.proto, ev.sni, ev.ja3, ev.ja4, ev.http_host,
            ev.dns_qname, ev.dst_ip, ev.feed_label)


def test_pcap_and_tzsp_paths_produce_identical_events(tmp_path):
    frames = _mixed_frames()
    # pcap path
    p = str(tmp_path / "m.pcap")
    write_pcap(p, frames)
    pcap_events = []
    ingest_pcap(p, FEED, pcap_events.append)
    # tzsp path: wrap each frame, decapsulate, parse, feed the same reassembler
    tz_events = []
    r = Reassembler(FEED, tz_events.append)
    for ts, frame in frames:
        pkt = bytes([1, 0]) + struct.pack("!H", 1) + bytes([tzsp.TZSP_TAG_END]) + frame
        lt, inner = tzsp.decapsulate(pkt)
        parsed = parse_frame(inner, lt)
        r.feed_packet(ts, parsed)
    r.finalize()
    assert sorted(map(_fields, pcap_events)) == sorted(map(_fields, tz_events))
    assert len(pcap_events) == 3


@pytest.mark.asyncio
async def test_live_sink_and_pcap_agree_on_protocol_fields(tmp_path):
    # same ClientHello bytes through the live socket and through pcap reassembly
    # must yield the same parsed protocol fields -- the equivalence the
    # architecture claims (transport-level fields like src_port legitimately differ)
    ch = build_client_hello("equal.example")

    sink_events = []
    sink = Sinkhole(FEED, sink_events.append, read_timeout=1.0)
    server = await sink.serve("127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        await send("127.0.0.1", port, ch)
    live = sink_events[0]

    frames = [
        (1.0, tcp_segment("100.64.0.9", "203.0.113.10", 5555, 443, 1000, flags=0x02)),
        (1.01, tcp_segment("100.64.0.9", "203.0.113.10", 5555, 443, 1001, ch)),
        (1.02, tcp_segment("100.64.0.9", "203.0.113.10", 5555, 443, 1001 + len(ch), b"", flags=0x11)),
    ]
    p = str(tmp_path / "ch.pcap")
    write_pcap(p, frames)
    pcap_events = []
    ingest_pcap(p, FEED, pcap_events.append)
    offline = pcap_events[0]

    assert live.proto == offline.proto == "tls"
    assert live.sni == offline.sni == "equal.example"
    assert live.ja3 == offline.ja3 and live.ja4 == offline.ja4
    assert live.tls_version == offline.tls_version and live.alpn == offline.alpn


# --- metrics ---------------------------------------------------------------

def test_metrics_record_and_render():
    m = Metrics()
    m.record_event("tls"); m.record_event("tls"); m.record_event("unknown")
    assert m.events == 3 and m.parse_failures == 1 and m.by_proto["tls"] == 2
    assert "c2sink_events 3" in m.render_prometheus()
    assert "parse_failures" in m.render_text()


@pytest.mark.asyncio
async def test_metrics_endpoint_serves_metrics_and_health():
    import asyncio
    from c2sink.metrics import serve_metrics
    m = Metrics(); m.record_event("tls")
    server = await serve_metrics("127.0.0.1", 0, m)
    port = server.sockets[0].getsockname()[1]
    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
        writer.close()
    assert b"200 OK" in data and b"c2sink_events 1" in data
