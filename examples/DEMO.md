# Reproduction run

Produced by `examples/reproduce.sh` on 2026-11-03 using the real
production mechanism: Linux `nat REDIRECT` plus `SO_ORIGINAL_DST`. Three
"subscribers" (distinct source IPs on 127.0.1.0/24) contact three blackholed
"C2" destinations (127.0.3.0/24, standing in for feed prefixes) on port 443;
the kernel redirects them to the sink, which recovers the true C2 address.

No real malware and no external traffic: payloads are crafted by
`c2sink.generate` and everything stays on loopback. Each connection returns
**zero bytes** from the sink (asserted in `tests/test_endtoend.py`).

Scenario:
- subscriber 127.0.1.11 beacons twice to the loader C2 (TLS, SNI api.exampleloader.cc), and also hits the proxy C2 -> shows one host talking to two C2s
- subscriber 127.0.1.12 talks to the stealer over plaintext HTTP (Host panel.examplestealer.su, /gate.php)
- subscriber 127.0.1.13 opens a raw TLS session with no SNI to the proxy C2 (distinct JA3)

```
c2sink listening on ('127.0.0.1', 18443); feed entries: 3
=== raw events (examples/repro_events.jsonl) ===
{"ts":1793691532.8749797,"src_ip":"127.0.1.11","src_port":36121,"dst_ip":"127.0.3.10","dst_port":443,"bytes_from_client":134,"proto":"tls","feed_label":"ExampleLoaderV4","sni":"api.exampleloader.cc","tls_version":772,"ja3":"28c903ee7c6f177a22c909a6806c1a63","alpn":["h2","http/1.1"],"http_host":null,"http_method":null,"http_target":null,"user_agent":null,"first_bytes_hex":"16030100810100007d0303000000000000000000000000000000000000000000","client_hello_complete":true}
{"ts":1793691532.876682,"src_ip":"127.0.1.11","src_port":45083,"dst_ip":"127.0.3.10","dst_port":443,"bytes_from_client":134,"proto":"tls","feed_label":"ExampleLoaderV4","sni":"api.exampleloader.cc","tls_version":772,"ja3":"28c903ee7c6f177a22c909a6806c1a63","alpn":["h2","http/1.1"],"http_host":null,"http_method":null,"http_target":null,"user_agent":null,"first_bytes_hex":"16030100810100007d0303000000000000000000000000000000000000000000","client_hello_complete":true}
{"ts":1793691532.87828,"src_ip":"127.0.1.12","src_port":44091,"dst_ip":"127.0.3.20","dst_port":443,"bytes_from_client":108,"proto":"http","feed_label":"ExampleStealer","sni":null,"tls_version":null,"ja3":null,"alpn":[],"http_host":"panel.examplestealer.su","http_method":"GET","http_target":"/gate.php","user_agent":"Mozilla/4.0 (compatible)","first_bytes_hex":"474554202f676174652e70687020485454502f312e310d0a486f73743a207061","client_hello_complete":null}
{"ts":1793691532.8794389,"src_ip":"127.0.1.13","src_port":60977,"dst_ip":"127.0.3.30","dst_port":443,"bytes_from_client":105,"proto":"tls","feed_label":"ExampleProxy","sni":null,"tls_version":772,"ja3":"77632da2117ede28f6b81655da556726","alpn":["h2","http/1.1"],"http_host":null,"http_method":null,"http_target":null,"user_agent":null,"first_bytes_hex":"1603010064010000600303000000000000000000000000000000000000000000","client_hello_complete":true}
{"ts":1793691532.8810287,"src_ip":"127.0.1.11","src_port":36225,"dst_ip":"127.0.3.30","dst_port":443,"bytes_from_client":133,"proto":"tls","feed_label":"ExampleProxy","sni":"cdn.exampleproxy.to","tls_version":772,"ja3":"28c903ee7c6f177a22c909a6806c1a63","alpn":["h2","http/1.1"],"http_host":null,"http_method":null,"http_target":null,"user_agent":null,"first_bytes_hex":"16030100800100007c0303000000000000000000000000000000000000000000","client_hello_complete":true}

=== subscriber report ===
Infected-subscriber report (passive sinkhole)
====================================================
subscribers that contacted a C2: 3

127.0.1.11
  connections : 3
  window      : 2026-11-03 07:38:52Z .. 2026-11-03 07:38:52Z
  c2 targets  : 127.0.3.10, 127.0.3.30
  feed labels : ExampleLoaderV4, ExampleProxy
  tls sni     : api.exampleloader.cc, cdn.exampleproxy.to
  ja3         : 28c903ee7c6f177a22c909a6806c1a63

127.0.1.12
  connections : 1
  window      : 2026-11-03 07:38:52Z .. 2026-11-03 07:38:52Z
  c2 targets  : 127.0.3.20
  feed labels : ExampleStealer
  http host   : panel.examplestealer.su
  user-agent  : Mozilla/4.0 (compatible)

127.0.1.13
  connections : 1
  window      : 2026-11-03 07:38:52Z .. 2026-11-03 07:38:52Z
  c2 targets  : 127.0.3.30
  feed labels : ExampleProxy
  ja3         : 77632da2117ede28f6b81655da556726

=== feed-health report ===
Feed-health report (what the sinkhole sees per listed destination)
==================================================================
listed destinations with traffic: 3

127.0.3.10  [ExampleLoaderV4]  LIVE
  hits / subscribers : 2 / 1
  last contact       : 2026-11-03 07:38:52Z  (0.0 h ago)
  names seen         : api.exampleloader.cc

127.0.3.30  [ExampleProxy]  LIVE
  hits / subscribers : 2 / 2
  last contact       : 2026-11-03 07:38:52Z  (0.0 h ago)
  names seen         : cdn.exampleproxy.to

127.0.3.20  [ExampleStealer]  LIVE
  hits / subscribers : 1 / 1
  last contact       : 2026-11-03 07:38:52Z  (0.0 h ago)
  names seen         : panel.examplestealer.su
```

Reproduce it yourself: `sudo ./examples/reproduce.sh` (needs root for iptables;
loopback only). Or run the offline end-to-end test: `PYTHONPATH=. python -m pytest -q`.
