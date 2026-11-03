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


def test_feed_health_aggregates_to_prefix_and_shows_dark_entries():
    from c2sink.feed import parse_feed
    from c2sink.report import build_health, render_health
    feed = parse_feed([
        "203.0.113.0/24 Loader",      # a /24: two different addresses hit should merge
        "198.51.100.5   Stealer",
        "192.0.2.0/24   Quiet",        # listed but no traffic -> must still appear
    ])
    events = [
        {"ts": 1000.0, "src_ip": "10.0.0.1", "dst_ip": "203.0.113.10", "proto": "tls",
         "sni": "a.bad.example", "http_host": None},
        {"ts": 1001.0, "src_ip": "10.0.0.2", "dst_ip": "203.0.113.200", "proto": "tls",
         "sni": "a.bad.example", "http_host": None},
    ]
    health = build_health(events, feed)
    # both addresses in the /24 aggregate to the one prefix
    assert health["203.0.113.0/24"].hits == 2
    assert health["203.0.113.0/24"].dst_ips == {"203.0.113.10", "203.0.113.200"}
    # the listed-but-silent prefix is present with zero hits (prune candidate)
    assert health["192.0.2.0/24"].hits == 0
    out = render_health(health, now=1002.0)
    assert "recently-seen" in out
    assert "no-traffic" in out and "prune candidate" in out
    # old traffic reads as "quiet", not a liveness claim
    assert "quiet" in render_health(health, now=1002.0 + 48 * 3600)


def test_ja4_matches_foxio_reference_vector():
    # FoxIO JA4 technical_details worked example (independent reference):
    #   t13d1516h2_8daaf6152771_e5627efa2ab1
    from c2sink.tls import ClientHello
    ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
               0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
    exts = [0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
            0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015]
    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    h = ClientHello(record_version=0x0303, hello_version=0x0303, ciphers=ciphers,
                    extensions=exts, supported_versions=[0x0304], sig_algs=sigs,
                    alpn=["h2", "http/1.1"], sni="example.com")
    assert h.ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_ja4_structure_and_sni_flag():
    from c2sink.tls import parse_client_hello
    from c2sink.generate import build_client_hello
    h = parse_client_hello(build_client_hello("login.example-cdn.net"))
    a, b, c = h.ja4.split("_")
    # a = t + version(2) + d/i + ciphers(2) + exts(2) + alpn(2)
    assert a[0] == "t" and a[1:3] == "13" and a[3] == "d"
    assert a[4:6] == "05" and a[6:8] == "06" and a[8:10] == "h2"
    assert len(b) == 12 and len(c) == 12
    assert h.ja4 == parse_client_hello(build_client_hello("login.example-cdn.net")).ja4
    # no SNI flips the flag to 'i' and drops one extension
    h2 = parse_client_hello(build_client_hello(None))
    assert h2.ja4.split("_")[0][3] == "i"


def test_beacon_detection():
    from c2sink.report import find_beacons
    # regular 60s interval from one src to one dst -> a beacon
    evs = [{"ts": 1000.0 + i * 60, "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9",
            "feed_label": "Loader"} for i in range(6)]
    # noise: a single contact elsewhere, should not be a beacon
    evs.append({"ts": 2000.0, "src_ip": "10.0.0.6", "dst_ip": "203.0.113.1", "feed_label": None})
    beacons = find_beacons(evs)
    assert len(beacons) == 1
    b = beacons[0]
    assert b.src_ip == "10.0.0.5" and b.dst_ip == "203.0.113.9"
    assert abs(b.mean_interval - 60.0) < 1e-6
    assert b.jitter < 0.01
