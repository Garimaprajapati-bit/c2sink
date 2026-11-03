# c2sink — find the infected customers behind a C2 blackhole

![demo](examples/demo.gif)


An ISP that blackholes a command-and-control (C2) prefix stops the bad traffic,
but it still doesn't know **which of its own subscribers are infected**. The
flows that would tell it are dropped at the edge.

`c2sink` turns the blackhole into a **passive sinkhole**: instead of dropping
C2-bound traffic, the ISP forwards it to one host that completes the TCP
handshake, records who connected and what they revealed, and **never sends a
byte of application data back**. The infected device receives no commands; the
operator gets a per-subscriber report.

It is meant as a companion to a BGP blackhole feed (such as the ones ISPs
already subscribe to): the same prefixes that are blackholed are the ones the
sink catches.

```
  infected host ──TCP SYN──▶  [ edge router: feed prefix ]
                                     │  (announce prefix with next-hop = sink,
                                     │   or REDIRECT to the sink)
                                     ▼
                               [ c2sink host ]
                                 • completes handshake
                                 • reads first bytes only
                                 • logs src, dst, SNI, JA3, HTTP host, time
                                 • sends nothing back, closes
                                     │
                                     ▼
                           per-subscriber report
```

## Why passive matters

The sink answers the handshake (the kernel does that) and then stays silent. It
does not impersonate the C2, does not issue commands and does not modify the
device. That keeps it on the right side of the line: it observes which
customers are infected so they can be notified, nothing more. "Un-infecting"
devices is deliberately out of scope.

## What it records

For every connection to a feed destination:
- source IP and port (the subscriber), destination IP and port (the C2),
  timestamp, bytes received;
- the feed's own label for that destination (whatever the feed knew);
- if the first bytes are a TLS ClientHello: the SNI, offered ALPN, negotiated
  version and a **JA3** fingerprint (GREASE-stripped), and whether the hello was
  complete or split across segments;
- if they are a plaintext HTTP request: method, target, Host and User-Agent;
- the first 32 bytes in hex, for anything else.

No decryption happens anywhere: the ClientHello and HTTP request head are
cleartext. The report attaches no attribution beyond the feed's label and the
raw observed fields.

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

# 3. two reports from the same log:
python -m c2sink report --log events.jsonl            # per subscriber (abuse desk)
python -m c2sink report --log events.jsonl --health   # per listed C2 (feed operator)
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
