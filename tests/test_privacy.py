"""Privacy and output-safety tests.

The two properties an ISP cares about:
- a subscriber's real IP never has to be written to disk (pseudonymisation),
  and the feed-operator view never carries a subscriber identifier;
- attacker-controlled names can't inject terminal escapes into a report.
"""

import json

from c2sink.analysis import build_event
from c2sink.capture import ingest_pcap
from c2sink.feed import FeedIndex, parse_feed
from c2sink.generate import (build_client_hello, build_http_get, dns_query,
                             tcp_segment, udp_datagram, write_pcap)
from c2sink.privacy import Pseudonymizer, load_salt, sanitize
from c2sink.report import build, build_health, render_health, render_text

FEED = FeedIndex(parse_feed(["203.0.113.0/24 Test"]))


def test_pseudonymizer_is_stable_salted_and_not_the_raw_ip():
    p1 = Pseudonymizer(b"salt-A")
    p2 = Pseudonymizer(b"salt-A")
    p3 = Pseudonymizer(b"salt-B")
    tok = p1.ip("100.64.0.9")
    assert tok == p2.ip("100.64.0.9")          # stable: same salt -> same token
    assert tok != p3.ip("100.64.0.9")          # salted: a different salt -> different token
    assert tok != p1.ip("100.64.0.10")         # distinct IPs -> distinct tokens
    assert "100.64.0.9" not in tok and tok.startswith("anon:")


def test_empty_salt_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        Pseudonymizer(b"")


def test_build_event_pseudonymizes_source_but_not_the_c2():
    p = Pseudonymizer(b"k")
    ev = build_event(1.0, "100.64.0.9", 5000, "203.0.113.10", 443,
                     build_client_hello("c2.example"), FEED, pseudonymizer=p)
    assert ev.src_ip == p.ip("100.64.0.9") and ev.src_ip.startswith("anon:")
    assert ev.dst_ip == "203.0.113.10"         # the C2 is threat intel, kept clear
    assert ev.sni == "c2.example"              # analysis still works


def test_pcap_ingest_log_contains_no_real_subscriber_ip(tmp_path):
    frames = [
        (1.0, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1000, flags=0x02)),
        (1.01, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 1001,
                           build_client_hello("c2.example"))),
        (1.02, tcp_segment("100.64.0.9", "203.0.113.10", 44001, 443, 9999, b"", flags=0x11)),
    ]
    p = str(tmp_path / "c.pcap")
    write_pcap(p, frames)
    logp = str(tmp_path / "events.jsonl")
    with open(logp, "w", encoding="utf-8") as fh:
        ingest_pcap(p, FEED, lambda ev: fh.write(ev.to_json_line() + "\n"),
                    pseudonymizer=Pseudonymizer(b"k"))
    body = open(logp, encoding="utf-8").read()
    assert "100.64.0.9" not in body and "anon:" in body


def test_feed_operator_view_never_shows_a_subscriber_ip():
    # the health report is the view shared with the feed operator; it must only
    # ever carry a count of sources, never the addresses themselves
    events = [
        build_event(1.0, "100.64.0.9", 5000, "203.0.113.10", 443,
                    build_client_hello("c2.example"), FEED),
        build_event(2.0, "100.64.0.42", 5000, "203.0.113.10", 443,
                    build_client_hello("c2.example"), FEED),
    ]
    out = render_health(build_health([vars(e) for e in events],
                                     parse_feed(["203.0.113.0/24 Test"])))
    assert "100.64.0.9" not in out and "100.64.0.42" not in out
    assert "sources" in out                     # the count is still reported


def test_sanitize_strips_terminal_escapes_and_bounds_length():
    nasty = "evil\x1b[31mred\x1b[0m\r\n\x07host.example"
    clean = sanitize(nasty)
    assert "\x1b" not in clean and "\r" not in clean and "\x07" not in clean
    assert "host.example" in clean
    assert sanitize("x" * 1000).endswith("...(truncated)")
    assert sanitize(None) is None


def test_report_sanitizes_attacker_controlled_host(tmp_path):
    # a crafted Host with an ANSI escape must not survive into the printed report
    ev = build_event(1.0, "100.64.0.9", 5000, "203.0.113.10", 443,
                     build_http_get("ok.example"), FEED)
    ev.http_host = "bad\x1b[2Jhost.example"       # simulate a logged escape
    out = render_text(build([vars(ev)]))
    assert "\x1b" not in out and "host.example" in out


def test_load_salt_prefers_value_then_file_then_env(tmp_path, monkeypatch):
    assert load_salt("direct") == b"direct"
    f = tmp_path / "s"
    f.write_text("fromfile\n")
    assert load_salt(None, str(f)) == b"fromfile"
    monkeypatch.setenv("C2SINK_SALT", "fromenv")
    assert load_salt() == b"fromenv"
    monkeypatch.delenv("C2SINK_SALT")
    assert load_salt() is None
