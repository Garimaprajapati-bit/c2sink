import ipaddress

from c2sink import tls, http
from c2sink.feed import FeedEntry, FeedIndex, parse_feed, iptables_rules
from c2sink.generate import build_client_hello, build_http_get


def test_parse_feed_v4_v6_and_labels():
    entries = parse_feed([
        "198.51.100.7            # host",
        "203.0.113.0/24  Mirai",
        "2001:db8:bad::/48 Emotet",
        "   ",
        "# comment only",
    ])
    assert len(entries) == 3
    assert entries[1].label == "Mirai"
    assert entries[2].is_v6


def test_feed_longest_prefix_lookup():
    idx = FeedIndex(parse_feed([
        "203.0.113.0/24 broad",
        "203.0.113.128/25 narrow",
    ]))
    assert idx.lookup("203.0.113.200").label == "narrow"
    assert idx.lookup("203.0.113.1").label == "broad"
    assert idx.lookup("8.8.8.8") is None


def test_client_hello_sni_and_ja3_stable():
    data = build_client_hello("login.example-cdn.net")
    hello = tls.parse_client_hello(data)
    assert hello is not None
    assert hello.sni == "login.example-cdn.net"
    assert hello.complete
    assert hello.max_version == 0x0304        # TLS 1.3 from supported_versions
    assert "h2" in hello.alpn
    # JA3 is deterministic and excludes the GREASE cipher 0x0a0a
    assert hello.ja3 == tls.parse_client_hello(data).ja3
    assert "2570" not in hello.ja3_string.split(",")[1].split("-")


def test_client_hello_truncated_is_reported_not_crashed():
    data = build_client_hello("split.example.net")
    hello = tls.parse_client_hello(data[:40])     # cut mid-hello
    assert hello is not None
    assert hello.complete is False


def test_non_tls_is_none():
    assert tls.parse_client_hello(b"GET / HTTP/1.1\r\n\r\n") is None
    assert tls.parse_client_hello(b"") is None


def test_http_request_parse():
    req = http.parse_request(build_http_get("panel.bad.example", "/gate.php", "Mozilla/4.0"))
    assert req is not None
    assert req.host == "panel.bad.example"
    assert req.target == "/gate.php"
    assert req.user_agent == "Mozilla/4.0"
    assert req.complete


def test_iptables_rules_pick_right_tool():
    rules = list(iptables_rules(parse_feed(["203.0.113.0/24", "2001:db8::/48"]), 8443))
    assert any("ip6tables -t nat -A C2SINK -d 2001:db8::/48" in r for r in rules)
    assert any("iptables -t nat -A C2SINK -d 203.0.113.0/24" in r for r in rules)


def test_feed_health_groups_by_destination():
    from c2sink.report import build_health, render_health
    events = [
        {"ts": 1000.0, "src_ip": "10.0.0.1", "dst_ip": "203.0.113.10", "proto": "tls",
         "sni": "a.bad.example", "feed_label": "Loader", "http_host": None},
        {"ts": 1001.0, "src_ip": "10.0.0.2", "dst_ip": "203.0.113.10", "proto": "tls",
         "sni": "a.bad.example", "feed_label": "Loader", "http_host": None},
        {"ts": 1002.0, "src_ip": "10.0.0.3", "dst_ip": "203.0.113.20", "proto": "tls",
         "sni": None, "feed_label": "Proxy", "http_host": None},
    ]
    health = build_health(events)
    assert set(health) == {"203.0.113.10", "203.0.113.20"}
    assert health["203.0.113.10"].hits == 2
    assert len(health["203.0.113.10"].sources) == 2
    assert health["203.0.113.20"].had_tls_without_sni is True
    # at ts just after, both are LIVE; far in the future both go dark
    assert "LIVE" in render_health(health, now=1003.0)
    assert "dark" in render_health(health, now=1003.0 + 48 * 3600)
