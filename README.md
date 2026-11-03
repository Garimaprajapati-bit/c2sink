# c2sink

A blackhole feed tells you which IPs are bad and you drop the traffic to them.
That works, but you throw away everything the dropped packets could have told
you: whether those C2s are still active, what the infected machines look like,
and whether a prefix you're blackholing has started catching normal traffic by
mistake.

c2sink keeps that information. Instead of dropping traffic to a listed prefix,
you point it at one host that answers the TCP handshake, reads the first few
bytes the client sends, writes down what it saw, and hangs up. It never sends
anything back. It's the "C2 emulator" idea without actually emulating a C2 —
just a quiet collector for the traffic a blackhole normally discards.

![what the sinkhole produces](examples/demo_output.png)

## What "passive" means here

The kernel completes the TCP handshake, because you can't read the first bytes
without it. After that the process does nothing: no reply, no C2 commands, no
tasking, no touching the device. It watches, it doesn't talk. There's an
end-to-end test that connects to the sink and checks it gets zero bytes back,
so that's not just a claim in a README.

It is not a takedown tool and it doesn't try to clean infected machines.

## What you get out of it

Each connection to a listed C2 is logged from the first read only — no
decryption, since the TLS ClientHello and the HTTP request line are both in the
clear. For TLS that's the SNI, ALPN, version and a JA4 and JA3 fingerprint
(GREASE stripped). For HTTP it's the method, path, Host and User-Agent. If the
ClientHello was split across packets, that's noted rather than dropped.

The reports are built from that log, offline:

- **Feed health** — per listed C2: how many hits, how many distinct sources,
  when it was last seen, and whether it still looks live. This is the one that
  matters if you run the feed: it tells you which entries are still earning
  their place.
- **False-positive candidates** — a prefix getting hit by lots of different
  sources that are all asking for a real-looking hostname is probably catching
  legitimate traffic, and worth a second look before it causes an outage.
- **Beaconing** — pairs that call the same C2 on a steady timer. Malware checks
  in on a schedule; people don't.
- **Subscriber view** — which internal IP talked to which C2. Useful for an
  abuse desk, but only before CGNAT. If you already get this from NetFlow, skip
  it; the fingerprint and feed-health parts are the new bits.

Nothing is attributed beyond the label your feed already carries.

## Running it

Python 3.11+, standard library only (asyncio). The tests want `pytest` and
`pytest-asyncio`.

```sh
# run the sink (v4 + v6), appending to a JSONL log
python -m c2sink serve --feed examples/feed.txt --port 8443 --log events.jsonl

# get the C2 traffic to it, either:
#   a) REDIRECT the feed prefixes to the sink on this host
python -m c2sink rules --feed examples/feed.txt --port 8443 | sudo sh
#   b) or announce them into your network with this host as next-hop (ExaBGP,
#      no-export so it stays inside your AS)
python -m c2sink rules --feed examples/feed.txt --exabgp \
    --nh4 192.0.2.10 --nh6 2001:db8::10 --community 65000:666

# then read the log
python -m c2sink report --log events.jsonl --health
python -m c2sink report --log events.jsonl --beacons
python -m c2sink report --log events.jsonl            # subscriber view
```

The feed file is one IP or CIDR per line, with an optional label:

```
203.0.113.0/24   Mirai
2001:db8:bad::/48 Emotet
198.51.100.10    # no label
```

Export your existing feed into that shape and you're done.

With Linux REDIRECT the sink recovers the real C2 address and port from
`SO_ORIGINAL_DST`, so one listener covers every prefix. With the ExaBGP
next-hop route the host receives the prefixes directly and the accept address
is the C2.

## Tests

```sh
PYTHONPATH=. python -m pytest -q
```

They cover the feed parsing and prefix lookup, the TLS parser (SNI, JA4/JA3,
GREASE, a truncated hello), HTTP parsing, rule generation, beacon detection,
and the end-to-end run that checks the sink stays silent.

## Known limits

- Only the first read is looked at; it never follows a conversation.
- Encrypted ClientHello hides the real SNI. You still see the outer name and
  that the connection happened; DNS-based controls are the fallback there.
- A ClientHello split across segments is recorded and flagged, not reassembled
  (yet).

## More detail

`ARCHITECTURE.md` has the component breakdown, why the sink sits before CGNAT,
how the original destination is recovered, and the failure modes. A full
captured run (real REDIRECT, three sources, three C2s) is in `examples/DEMO.md`;
`sudo ./examples/reproduce.sh` regenerates it.

This is a working prototype, not something that's been run against a live feed
yet.
