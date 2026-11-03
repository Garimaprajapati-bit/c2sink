# c2sink — turn a C2 blackhole into live threat intelligence

![demo](examples/demo.gif)


A BGP C2 blackhole feed stops traffic to known command-and-control (C2)
infrastructure, but the dropped packets could tell the operator a great deal:
which C2s are still live, what the infected clients look like, and whether a
listed prefix is starting to catch legitimate traffic. The blackhole throws
that away.

`c2sink` keeps it. Instead of dropping C2-bound traffic, the network forwards
it to one **passive** host that completes the TCP handshake, reads only the
first bytes the client sends, and records them. It is a telemetry collector for
redirected botnet traffic — the "C2 emulator" idea, minus any emulation of the
C2 itself.

```
  infected host ──TCP SYN──▶  [ edge router: feed prefix ]
                                     │  announce prefix with next-hop = sink,
                                     │  or REDIRECT to the sink
                                     ▼
                               [ c2sink host ]  (passive)
                                 • completes the TCP handshake (kernel only)
                                 • reads the first bytes, never writes back
                                 • records dst (C2), src, SNI, JA4/JA3, HTTP, time
                                     │
                     ┌───────────────┼────────────────┐
              feed-health        beaconing        subscriber view
         (live/dark, FP signal) (call-home timing) (abuse desk; optional)
```

## The passive boundary (exactly what it does and does not do)

| | |
|---|---|
| TCP handshake | completed by the **kernel** (unavoidable to receive the first bytes) |
| Application-level response | **none** — the sink never writes a byte back |
| C2 commands / tasking | **none** |
| Payload execution | **none** |

The sink is an observer, not a C2 impersonator. It does not task, modify or
"un-infect" devices. The end-to-end test asserts that every connection returns
**zero bytes** from the sink, so this boundary is demonstrated, not just claimed.

## What it extracts (the intelligence)

For every connection to a listed destination, from the first read only, no
decryption (the ClientHello and HTTP request head are cleartext):

- **TLS client fingerprint**: **JA4** (FoxIO) and JA3, both GREASE-stripped,
  plus SNI, offered ALPN and negotiated version — identifies the client stack
  even across IPs and SNIs.
- **HTTP metadata**: method, target, Host, User-Agent.
- **Completeness**: whether the ClientHello was whole or split across segments.
- The first 32 bytes in hex for anything else.

From the event log it then derives:

- **Feed health** (per listed C2): hits, unique subscribers, last contact, and
  **live/dark** classification — which feed entries are still worth listing.
- **False-positive candidates**: a listed prefix contacted by many distinct
  subscribers with a named service, i.e. possibly legitimate traffic caught by
  the prefix.
- **Beaconing**: source→C2 pairs whose contacts arrive on a regular timer, the
  signature of automated call-home rather than a human.
- **Subscriber view** (optional, for an ISP's own abuse desk): which internal
  IPs contacted which C2s. Most useful *before CGNAT*; an operator that already
  derives this from NetFlow can ignore it and keep the feed-health and
  fingerprint intelligence.

No attribution beyond the feed's own label and the raw observed fields.

## Install

Pure standard-library Python 3.11+ (asyncio). Tests need `pytest` and
`pytest-asyncio`.

```sh
pip install pytest pytest-asyncio   # tests only
```

## Use

```sh
# 1. run the sink (binds v4+v6; append to a JSONL log)
python -m c2sink serve --feed examples/feed.txt --port 8443 --log events.jsonl

# 2. send C2-bound traffic to it (choose one):
#    a) on the sink host, REDIRECT the feed prefixes to the sink port:
python -m c2sink rules --feed examples/feed.txt --port 8443 | sudo sh
#    b) or announce the feed prefixes into your network with the sink as
#       next-hop, via ExaBGP (no-export, stays inside your AS):
python -m c2sink rules --feed examples/feed.txt --exabgp \
    --nh4 192.0.2.10 --nh6 2001:db8::10 --community 65000:666

# 3. reports from the same log:
python -m c2sink report --log events.jsonl --health   # per listed C2: live/dark, false positives
python -m c2sink report --log events.jsonl --beacons  # regular call-home patterns
python -m c2sink report --log events.jsonl            # per subscriber (abuse desk; optional)
```

### Feed format

One IPv4/IPv6 address or CIDR per line, optional `# comment`, optional label:

```
203.0.113.0/24  Mirai
2001:db8:bad::/48 Emotet
198.51.100.10   # no label
```

Export your existing blackhole feed into this and nothing else changes.

## Original-destination recovery

- With Linux `REDIRECT`, the sink reads the real C2 address via
  `SO_ORIGINAL_DST`, so one listener serves every prefix and the report shows
  the true destination.
- With the ExaBGP next-hop approach, the sink host receives the packets for the
  announced prefixes directly; the accept address is the C2 address.

## Tests

```sh
PYTHONPATH=. python -m pytest -q
```

Covers feed parsing and longest-prefix lookup, TLS ClientHello parsing (SNI,
stable JA3, GREASE handling, truncated hello), HTTP parsing, rule generation,
and an end-to-end run proving the sink records a connection **and replies with
zero bytes**.

## Limits (by design, and known)

- Only the first read is inspected; the sink never continues a conversation.
- With Encrypted ClientHello (ECH) the real SNI is hidden; the outer name and
  the fact of the connection are still recorded. DNS-side controls remain the
  fallback there.
- A ClientHello split across TCP segments is recorded and flagged
  `complete:false`; reassembly across reads is a possible extension.
- This identifies infected subscribers; it is not a takedown tool.

## Design

See `ARCHITECTURE.md` for the component layout, the placement decision
(before CGNAT, like NetFlow), original-destination recovery, and failure modes.

## Status

Prototype built as a concrete proposal, not a finished product. Everything here
runs and is tested; it has not been deployed against a live feed. The captured
reproduction (real `nat REDIRECT` + `SO_ORIGINAL_DST`, three subscribers, three
C2s) is in `examples/DEMO.md`; rerun it with `sudo ./examples/reproduce.sh`.
