# Architecture

## Problem

A BGP blackhole feed (botnet.cl and similar) distributes C2 prefixes that
subscribing ISPs route to discard. This stops the C2 traffic, but it throws
away the one thing the operator could learn from it: **who inside the network
was talking to that C2, and what they are.** The packets that carry that
answer are dropped at the edge.

`c2sink` keeps those packets instead of dropping them, in a way that is safe to
run and cheap to deploy, and turns them into two outputs: a per-subscriber view
(for the ISP's abuse desk) and a per-destination view (for the feed operator).

## Where it sits

```
                 BGP (feed prefixes)
 botnet.cl ───────────────────────────▶ subscriber ISP edge routers
                                               │
                 instead of null-route, send feed prefixes to the sink:
                 (a) announce them with next-hop = sink host (iBGP, no-export), or
                 (b) nat REDIRECT on a router / the sink host itself
                                               │
                                        ┌──────▼───────┐
                                        │   c2sink     │  one host
                                        │  (asyncio)   │
                                        └──────┬───────┘
                                  JSONL event log (append-only)
                                               │
                               ┌───────────────┴───────────────┐
                        subscriber report                 feed-health report
                        (abuse desk)                      (feed operator)
```

Placement matters and is a deliberate choice, not an accident:
- To attribute traffic to a **subscriber**, the sink must see the real client
  address, so it sits **before CGNAT**, exactly where an operator already puts
  NetFlow collection for the same reason. Behind CGNAT it would only see the
  NAT pool address and must instead correlate by 5-tuple and time with the
  operator's existing flow records.
- To improve the **feed**, placement doesn't matter: any traffic reaching any
  listed prefix is a signal about that prefix.

## Components (one responsibility each)

| Module | Responsibility |
|---|---|
| `feed.py` | Parse the feed; longest-prefix lookup; emit REDIRECT / ExaBGP rules. |
| `server.py` | Accept, recover the original destination, read the first bytes, build an `Event`, never write back, close. |
| `analysis.py` | The one place a captured first-payload becomes an `Event` (TLS, HTTP, DNS, QUIC). Both the live sink and the pcap/TZSP path call it. |
| `packet.py` | Parse a link-layer frame to a transport payload (Ethernet/raw/SLL, IPv4/IPv6, TCP/UDP). |
| `pcap.py` / `tzsp.py` | Read a classic pcap file; decapsulate a TZSP-wrapped frame. |
| `capture.py` | Reassemble packets into events: TCP in the client→server direction (so a split ClientHello is rejoined), UDP's first datagram per flow. `ingest_pcap` and `serve_tzsp` feed the same reassembler. |
| `tls.py` | Parse a (possibly truncated) TLS ClientHello: SNI, versions, ALPN, JA4 and JA3. |
| `http.py` / `dns.py` / `quic.py` | HTTP request head; DNS query name; QUIC Initial detection. |
| `report.py` | Derive from the event log: feed health (per prefix), beaconing (per src→C2 pair), and the subscriber view. |
| `writer.py` | Durable, bounded event writer: non-blocking submit, background drain to append-only JSONL, counts drops/write-errors, defined flush/shutdown. |
| `metrics.py` | Operational counters for the collector itself + a read-only `/metrics` (Prometheus) and `/healthz` endpoint. |
| `privacy.py` | Subscriber-IP pseudonymisation (salted HMAC) and output sanitisation. |
| `generate.py` | Craft ClientHello / HTTP / pcaps for tests and demos (no real malware). |
| `__main__.py` | `serve` / `ingest` / `report` / `rules` CLI. |

There are three layers, kept independent so each can change without the others:
**capture** (`server.py` live, `capture.py` pcap/TZSP, `packet.py`/`pcap.py`/
`tzsp.py`) only produces payloads; **protocol** (`analysis.py` with `tls`,
`http`, `dns`, `quic`) turns a payload into an `Event`; **intelligence**
(`report.py`) reads the event log. A capture source's only job is to hand
`analysis.build_event` a 5-tuple and the first payload, so pcap replay, a live
TZSP mirror and the live sink all yield identical events and identical reports.
The parsers are pure functions of `bytes -> dataclass`, so they unit-test and
fuzz directly; the reports depend only on the log.

The intelligence lives entirely in `report.py`, computed offline from the log:
**JA4/JA3** client fingerprints (in `tls.py`) survive IP and SNI changes — the
JA4 output is checked against FoxIO's published reference vector in the tests;
**feed health** takes the feed plus the log, aggregates traffic to each feed
prefix (so a /24 is one row, not many), includes listed prefixes that saw *no*
traffic as prune candidates, and flags possible false positives (many distinct
sources + a named service) — a row is "recently-seen" or "quiet" by when the
prefix was last hit, which is not a claim about the C2 host itself; **beaconing**
groups by (src, C2) and flags pairs whose inter-arrival times are regular enough
(low coefficient of variation) to look automated rather than human. Adding an
analysis is a new pure function over the log, never a change to capture.

## Key design decisions

1. **Passive by construction.** The server reads once and closes; there is no
   code path that writes application data to a client. The kernel completes the
   TCP handshake (unavoidable to receive the first bytes), nothing more:

   | TCP handshake | kernel only | Application response | none |
   | C2 commands | none | Payload execution | none |

   This keeps the tool an observer, not a C2 impersonator, which is both an
   ethical and a legal line. The end-to-end test asserts zero bytes are
   returned, so the boundary is demonstrated, not just asserted.

2. **Original-destination recovery via `SO_ORIGINAL_DST`.** With nat REDIRECT,
   one listener serves every prefix and still records the true C2 address and
   port (verified in the reproduction). Without REDIRECT (ExaBGP next-hop mode)
   the accept address is the C2 address. One code path, two deployments.

3. **Append-only JSONL as the interface between capture and analysis.** The
   server only appends events; all aggregation is offline and re-runnable. A
   bug in a report never costs captured data, and the log can be shipped to the
   operator's existing SIEM unchanged.

4. **Truncation is data, not an error.** A ClientHello split across TCP
   segments is recorded with `client_hello_complete: false` rather than
   dropped, so the operator sees the connection even when the first read is
   partial. (Reassembly across reads is a documented future extension.)

5. **No attribution beyond evidence.** The tool reports the feed's own label
   and the raw observed fields (SNI, JA3, Host). It does not ship a malware
   signature database or guess families; that avoids both false precision and
   turning a defensive tool into something it shouldn't be.

## Failure modes and limits

- **ECH**: the real SNI is encrypted; the outer name and the connection are
  still recorded. DNS-side controls remain the fallback.
- **CGNAT**: see placement above.
- **Load**: asyncio with a bounded first read (`read_bytes`, `read_timeout`)
  and immediate close; the sink does no per-connection work beyond one parse,
  so a flood costs one accept + one read each. A hard concurrency cap is a
  deployment knob (systemd `LimitNOFILE`, or an accept semaphore) and a
  documented extension.
- **Trust**: an ISP running this sees its own customers' destination metadata,
  which it already sees in NetFlow; the feed operator sees only per-prefix
  aggregates unless an ISP chooses to share more.

## Capture-path contract

The three capture sources are different mechanisms, and the architecture's claim
that they produce equivalent events is a claim that has to be demonstrated, not
assumed. The common contract is:

```
capture source → normalized observation (5-tuple + first client payload) → build_event → Event
```

What each source can and cannot observe differs, and that difference is explicit:

| Capture source | Sees | Gets the first payload via | Equivalence |
|---|---|---|---|
| **pcap replay** | whole packets as captured | TCP reassembly (client→server), UDP first datagram | reference path |
| **live TZSP mirror** | whole packets (same frames, TZSP-wrapped) | same packet parser + same reassembler | **identical** events to pcap for the same frames (tested) |
| **live sink** | a completed handshake + socket bytes | one socket read (the kernel already reassembled) | **same parsed protocol fields** (SNI/JA3/JA4/ALPN/version) for the same ClientHello; transport-level fields such as the source port legitimately differ (tested) |

So: pcap and TZSP go through `packet.py` + `capture.py` and yield byte-identical
events; the live sink skips reassembly (the kernel did it) but feeds the same
`build_event`, so the *protocol* fields match. Both equivalences are asserted in
`tests/test_production.py`, not just stated here.

## Resource bounds and reliability

Hostile traffic must not be able to exhaust memory or silently lose data. The
bounds are:

- **Per-flow:** at most `max_bytes` buffered and 64 segments; overlapping or
  retransmitted segments are resolved first-writer-wins (a later packet cannot
  overwrite earlier data — anti-evasion and anti-corruption).
- **Per-table:** at most `max_flows` concurrent flows; over the cap the
  oldest-inserted flow is evicted in O(1). A flow idle for `idle_timeout`, or
  open longer than `max_duration`, is flushed (emitting the honest partial) and
  freed. Buffers are freed on FIN/RST and on timeout.
- **Event writing:** a bounded in-memory queue drained by a background thread to
  an append-only JSONL file. `submit()` never blocks the capture path; when the
  queue is full, the event is dropped and **counted** (`events_dropped`), so
  backpressure is visible. Write errors (e.g. a full disk) are counted and the
  collector keeps running. The reader tolerates a torn final line from a crash.
- **Observability:** `metrics.py` exposes packets, events, parse failures,
  reassembly timeouts, segments deduped, flows evicted, events written/dropped,
  write errors, active flows and queue depth — as an end-of-run summary
  (`ingest`) or a `/metrics` scrape endpoint (`serve --metrics-port`).

A synthetic benchmark (`examples/benchmark.py`) drives a mix of complete,
never-closing, scan-only and retransmit-storm flows through the full pipeline.
On one core it sustains ~110k packets/s with peak RSS bounded to tens of MiB
regardless of flow count; event accounting always balances
(`written + dropped == produced`), and with an adequately sized writer queue the
drop count is zero.

## Event schema versioning

Every `Event` carries `schema_version` (`analysis.SCHEMA_VERSION`). It is bumped
when a field's meaning changes or one is removed, not for purely additive
fields, so a downstream reader or SIEM can branch on it; readers tolerate an
unknown (newer) version rather than failing.

## Testing

- Unit: feed parsing and longest-prefix match, ClientHello parsing (SNI, stable
  GREASE-stripped JA3, truncated hello), HTTP parsing, rule generation, both
  report builders.
- End-to-end: a live server on loopback, synthetic traffic, asserting both the
  recorded metadata and that the server returns **zero bytes**.
- Reproduction (`examples/reproduce.sh`): the real nat REDIRECT +
  `SO_ORIGINAL_DST` path with several distinct subscribers and C2 destinations,
  producing both reports from captured output.
