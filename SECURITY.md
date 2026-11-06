# Security and privacy

This tool captures traffic that, on the client side, belongs to the operator's
own subscribers, and on the server side belongs to hostile hosts. Both sides
need care. This document states the threat model and the controls, and is
honest about what the controls do and don't guarantee.

## What the sink does and does not do

- It reads only the first bytes a client sends and then closes. There is no
  code path that writes application data back to a client (an end-to-end test
  asserts zero bytes are returned), so it is an observer, not a C2 impersonator.
- It never decrypts anything. SNI and the HTTP request line are already in the
  clear; nothing else is read.
- It does not store full payloads. Each event records parsed metadata plus the
  first 32 bytes as hex (handshake/method bytes, not credentials or cookies —
  those live further into a request than the sink ever reads).
- The parsers are pure `bytes -> dataclass` functions, fuzzed against arbitrary
  input (`tests/test_hardening.py`): malformed packets return `None` or a
  partial result, never an exception or an out-of-bounds read.

## Subscriber privacy

The client address identifies a subscriber, so it is treated as the sensitive
field.

- **Pseudonymisation (`--pseudonymize`).** The source IP is replaced with a
  salted HMAC-SHA256 token (`anon:<hex>`) *before anything is written to disk*,
  so a deployment that only improves the feed never records a real subscriber
  address. The token is stable within a dataset (you can still count distinct
  sources and detect beaconing) and is keyed by a secret salt supplied out of
  band (`--salt-file` or the `C2SINK_SALT` environment variable; never
  committed). The C2 (destination) address is **not** pseudonymised — it is
  intelligence about an attacker, not data about a person.

  This is pseudonymisation, not anonymisation. The IPv4 space is small, so a
  party who holds the salt can brute-force the mapping. The salt is therefore a
  secret, and this control reduces exposure (a leaked or shared log is not
  trivially re-identifiable) rather than guaranteeing anonymity.

- **The feed-operator view carries no subscriber identifier.** The feed-health
  report (the view meant to be shared back with the feed operator) reports a
  *count* of distinct sources per prefix, never the addresses. This is asserted
  by a test (`test_feed_operator_view_never_shows_a_subscriber_ip`). The
  per-subscriber view, which does contain the (possibly pseudonymised) source,
  is internal to the operator's abuse desk.

- **Lawful basis and retention.** This is the same category of data an operator
  already collects with NetFlow at the same point in the network (before
  CGNAT). Run it under the same legal basis, access controls and retention
  schedule as your existing flow records; the JSONL log should be access
  controlled and rotated/expired like any other flow data. Pseudonymise unless
  there is a concrete abuse-handling reason to keep raw source addresses.

## Running the sink safely

- **Privilege separation.** The sink needs root only to bind a low port and to
  read `SO_ORIGINAL_DST` on redirected sockets; it must not keep root while
  parsing attacker-controlled bytes. Pass `--user <account>` and it drops to
  that unprivileged account immediately after binding (and after binding the
  metrics port), before serving. Supplementary groups and the gid are dropped
  before the uid, the drop is **verified** (it asserts it cannot regain root),
  and on Linux it sets `PR_SET_NO_NEW_PRIVS` so no later exec can re-escalate.
  Deploy it as a non-root service whose only elevated step is the redirect/
  capture setup, keep the feed and config files **read-only** to the collector
  account, and the event log is created mode `0600` (it holds subscriber
  metadata).
- **Resource bounds.** The first read is bounded (`read_bytes`, `read_timeout`)
  and the connection is closed immediately, so a flood costs one accept + one
  read each. The reassembler bounds its flow table and dedup set
  (`max_flows`), so a long-running live capture cannot grow memory without
  limit. A hard concurrency cap (systemd `LimitNOFILE` or an accept semaphore)
  is a deployment knob.
- **Output safety.** SNI, HTTP Host/User-Agent and DNS names are attacker
  controlled. The JSONL log is safe (JSON escapes control bytes), and the
  human-readable reports strip control and ANSI-escape characters before
  printing, so a crafted name cannot inject terminal sequences into an
  operator's console.

## Reporting

This is a prototype. If you find a parsing or memory-safety issue, a crafted
pcap that reproduces it is the most useful thing to include.
