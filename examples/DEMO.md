# Reproduction run

Produced by `examples/reproduce.sh` using the real production mechanism: Linux
`nat REDIRECT` plus `SO_ORIGINAL_DST`. Three sources (on 127.0.1.0/24) contact
blackholed destinations (127.0.3.0/24) on port 443; the kernel redirects them to
the sink, which recovers the true C2 address. The feed lists a /24, two single
hosts, and one quiet /24 that gets no traffic (a prune candidate). The beaconing
section runs on a timed sample (`examples/beacon_sample.jsonl`), since a fast
loopback run has no timing to analyse.

No real malware, no external traffic: payloads are crafted by `c2sink.generate`
and everything stays on loopback. Each connection returns **zero bytes** from
the sink (asserted in `tests/test_endtoend.py`).

```
c2sink listening on ('127.0.0.1', 18443); feed entries: 4
=== raw events (examples/repro_events.jsonl) ===
{"ts":1793742493.360856,"src_ip":"127.0.1.11","src_port":41599,"dst_ip":"127.0.3.10","dst_port":443,"bytes_from_client":146,"proto":"tls","feed_label":"ExampleLoaderNet","sni":"api.exampleloader.cc","tls_version":772,"ja3":"637f6ed8b841a5a54460abea6667e41d","ja4":"t13d0506h2_8d80437dd348_0d385148b956","alpn":["h2","http/1.1"],"http_host":null,"http_method":null,"http_target":null,"user_agent":null,"first_bytes_hex":"160301008d010000890303000000000000000000000000000000000000000000","client_hello_complete":true}
{"ts":1793742493.36272,"src_ip":"127.0.1.11","src_port":37865,"dst_ip":"127.0.3.11","dst_port":443,"bytes_from_client":146,"proto":"tls","feed_label":"ExampleLoaderNet","sni":"api.exampleloader.cc","tls_version":772,"ja3":"637f6ed8b841a5a54460abea6667e41d","ja4":"t13d0506h2_8d80437dd348_0d385148b956","alpn":["h2","http/1.1"],"http_host":null,"http_method":null,"http_target":null,"user_agent":null,"first_bytes_hex":"160301008d010000890303000000000000000000000000000000000000000000","client_hello_complete":true}
{"ts":1793742493.3642018,"src_ip":"127.0.1.12","src_port":40571,"dst_ip":"127.0.3.20","dst_port":443,"bytes_from_client":108,"proto":"http","feed_label":"ExampleStealer","sni":null,"tls_version":null,"ja3":null,"ja4":null,"alpn":[],"http_host":"panel.examplestealer.su","http_method":"GET","http_target":"/gate.php","user_agent":"Mozilla/4.0 (compatible)","first_bytes_hex":"474554202f676174652e70687020485454502f312e310d0a486f73743a207061","client_hello_complete":null}
{"ts":1793742493.3654814,"src_ip":"127.0.1.13","src_port":40255,"dst_ip":"127.0.3.30","dst_port":443,"bytes_from_client":117,"proto":"tls","feed_label":"ExampleProxy","sni":null,"tls_version":772,"ja3":"ed8b5be1d20e0b70ea77f42dcaefec32","ja4":"t13i0505h2_8d80437dd348_0d385148b956","alpn":["h2","http/1.1"],"http_host":null,"http_method":null,"http_target":null,"user_agent":null,"first_bytes_hex":"16030100700100006c0303000000000000000000000000000000000000000000","client_hello_complete":true}
{"ts":1793742493.3667035,"src_ip":"127.0.1.11","src_port":36619,"dst_ip":"127.0.3.30","dst_port":443,"bytes_from_client":145,"proto":"tls","feed_label":"ExampleProxy","sni":"cdn.exampleproxy.to","tls_version":772,"ja3":"637f6ed8b841a5a54460abea6667e41d","ja4":"t13d0506h2_8d80437dd348_0d385148b956","alpn":["h2","http/1.1"],"http_host":null,"http_method":null,"http_target":null,"user_agent":null,"first_bytes_hex":"160301008c010000880303000000000000000000000000000000000000000000","client_hello_complete":true}

=== feed-health report (live/dark, false-positive signal) ===
Feed-health report (traffic seen per listed prefix)
====================================================
listed prefixes: 4   with traffic: 3

127.0.3.30/32  [ExampleProxy]  recently-seen
  hits / sources     : 2 / 2
  last seen          : 2026-11-03 21:48:13Z  (0.0 h ago)
  names seen         : cdn.exampleproxy.to

127.0.3.0/24  [ExampleLoaderNet]  recently-seen
  hits / sources     : 2 / 1
  last seen          : 2026-11-03 21:48:13Z  (0.0 h ago)
  addresses hit      : 127.0.3.10, 127.0.3.11
  names seen         : api.exampleloader.cc

127.0.3.20/32  [ExampleStealer]  recently-seen
  hits / sources     : 1 / 1
  last seen          : 2026-11-03 21:48:13Z  (0.0 h ago)
  names seen         : panel.examplestealer.su

127.0.9.0/24  [ExampleQuiet]  no-traffic
  nothing seen in this window (prune candidate)

=== subscriber report (abuse desk; optional) ===
Infected-subscriber report (passive sinkhole)
====================================================
subscribers that contacted a C2: 3

127.0.1.11
  connections : 3
  window      : 2026-11-03 21:48:13Z .. 2026-11-03 21:48:13Z
  c2 targets  : 127.0.3.10, 127.0.3.11, 127.0.3.30
  feed labels : ExampleLoaderNet, ExampleProxy
  tls sni     : api.exampleloader.cc, cdn.exampleproxy.to
  ja4         : t13d0506h2_8d80437dd348_0d385148b956
  ja3         : 637f6ed8b841a5a54460abea6667e41d

127.0.1.12
  connections : 1
  window      : 2026-11-03 21:48:13Z .. 2026-11-03 21:48:13Z
  c2 targets  : 127.0.3.20
  feed labels : ExampleStealer
  http host   : panel.examplestealer.su
  user-agent  : Mozilla/4.0 (compatible)

127.0.1.13
  connections : 1
  window      : 2026-11-03 21:48:13Z .. 2026-11-03 21:48:13Z
  c2 targets  : 127.0.3.30
  feed labels : ExampleProxy
  ja4         : t13i0505h2_8d80437dd348_0d385148b956
  ja3         : ed8b5be1d20e0b70ea77f42dcaefec32

=== beaconing report (on the timed sample examples/beacon_sample.jsonl) ===
Beaconing (regular automated call-home patterns)
================================================

100.64.12.37 -> 203.0.113.10  [ExampleLoader]
  6 contacts, every ~300s (jitter 0%)
  2026-11-02 06:13:20Z .. 2026-11-02 06:38:20Z
```

Reproduce it yourself: `sudo ./examples/reproduce.sh` (root for iptables,
loopback only). Offline tests: `PYTHONPATH=. python -m pytest -q`.
