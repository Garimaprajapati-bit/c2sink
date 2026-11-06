"""Command-line entry point.

    python -m c2sink serve   --feed feed.txt --port 8443 --log events.jsonl
    python -m c2sink report  --log events.jsonl [--json]
    python -m c2sink rules   --feed feed.txt --port 8443 [--exabgp --nh4 X --nh6 Y]
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .feed import FeedIndex, exabgp_announcements, iptables_rules, load_feed
from .report import (build, build_health, find_beacons, load_events,
                     render_beacons, render_health, render_json, render_text)
from .server import Sinkhole


def _make_pseudonymizer(args):
    """Build a Pseudonymizer if the operator asked for one, else None. Fails
    loudly rather than silently logging real addresses when a salt is missing."""
    from .privacy import Pseudonymizer, load_salt
    if not getattr(args, "pseudonymize", False):
        return None
    salt = load_salt(getattr(args, "salt", None), getattr(args, "salt_file", None))
    if not salt:
        print("--pseudonymize needs a salt: pass --salt, --salt-file, or set C2SINK_SALT",
              file=sys.stderr)
        raise SystemExit(2)
    return Pseudonymizer(salt)


def _serve(args) -> int:
    from .metrics import Metrics, serve_metrics
    from .server import drop_privileges
    from .writer import EventWriter

    pseud = _make_pseudonymizer(args)
    entries = load_feed(args.feed)
    index = FeedIndex(entries)
    metrics = Metrics()
    writer = EventWriter(args.log, metrics=metrics, max_queue=args.max_queue, fsync=args.fsync)

    def on_event(ev):
        writer.submit_event(ev)             # non-blocking; drops are counted, not hidden
        if not args.quiet:
            who = ev.sni or ev.http_host or ev.proto
            print(f"[{ev.proto}] {ev.src_ip} -> {ev.dst_ip}:{ev.dst_port} {who}", file=sys.stderr)

    sink = Sinkhole(index, on_event, read_bytes=args.max_bytes,
                    linger_seconds=args.linger, pseudonymizer=pseud, metrics=metrics)

    async def run():
        server = await sink.serve(args.host, args.port)
        mserver = await serve_metrics(args.metrics_host, args.metrics_port, metrics) \
            if args.metrics_port else None
        if args.user:                       # after every privileged bind, before serving
            drop_privileges(args.user)
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
        extra = []
        if pseud:
            extra.append("subscriber IPs pseudonymised")
        if mserver is not None:
            extra.append(f"metrics on :{args.metrics_port}/metrics")
        print(f"c2sink listening on {addrs}; feed entries: {len(index)}"
              + (f"; {', '.join(extra)}" if extra else ""), file=sys.stderr)
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    finally:
        writer.close()
        if not args.quiet:
            print(metrics.render_text(), file=sys.stderr)
    return 0


def _ingest(args) -> int:
    from .capture import ingest_pcap
    from .feed import FeedIndex, load_feed
    from .metrics import Metrics
    from .writer import EventWriter
    pseud = _make_pseudonymizer(args)
    index = FeedIndex(load_feed(args.feed))
    metrics = Metrics()
    with EventWriter(args.log, metrics=metrics, max_queue=args.max_queue, fsync=args.fsync) as writer:
        def on_event(ev):
            writer.submit_event(ev)
            if not args.quiet:
                who = ev.sni or ev.http_host or ev.dns_qname or ev.proto
                print(f"[{ev.transport}/{ev.proto}] {ev.src_ip} -> {ev.dst_ip}:{ev.dst_port} {who}",
                      file=sys.stderr)
        n = ingest_pcap(args.pcap, index, on_event, max_bytes=args.max_bytes,
                        pseudonymizer=pseud, metrics=metrics, max_flows=args.max_flows,
                        idle_timeout=args.idle_timeout, max_duration=args.max_duration)
    print(f"read {n} packets from {args.pcap}", file=sys.stderr)
    if not args.quiet:
        print(metrics.render_text(), file=sys.stderr)
    return 0


def _report(args) -> int:
    events = load_events(args.log)
    if args.health:
        from .feed import load_feed
        entries = load_feed(args.feed) if args.feed else None
        print(render_health(build_health(events, entries)))
    elif args.beacons:
        print(render_beacons(find_beacons(events)))
    else:
        subs = build(events)
        print(render_json(subs) if args.json else render_text(subs))
    return 0


def _rules(args) -> int:
    entries = load_feed(args.feed)
    if args.exabgp:
        if not (args.nh4 and args.nh6):
            print("--exabgp needs --nh4 and --nh6", file=sys.stderr)
            return 2
        for line in exabgp_announcements(entries, args.nh4, args.nh6, args.community):
            print(line)
    else:
        for line in iptables_rules(entries, args.port):
            print(line)
    return 0


def _add_privacy_flags(parser) -> None:
    parser.add_argument("--pseudonymize", action="store_true",
                        help="replace subscriber (source) IPs with a salted token before logging")
    parser.add_argument("--salt", help="salt for --pseudonymize (prefer --salt-file or C2SINK_SALT)")
    parser.add_argument("--salt-file", help="read the pseudonymisation salt from this file")


def _add_writer_flags(parser) -> None:
    parser.add_argument("--max-bytes", type=int, default=16384,
                        help="max bytes read/reassembled per flow")
    parser.add_argument("--max-queue", type=int, default=10000,
                        help="writer queue depth; events are dropped (and counted) when full")
    parser.add_argument("--fsync", action="store_true", help="fsync the log on each flush")


def _add_flow_flags(parser) -> None:
    parser.add_argument("--max-flows", type=int, default=4096,
                        help="max concurrent TCP flows tracked")
    parser.add_argument("--idle-timeout", type=float, default=60.0,
                        help="flush a flow after this many seconds idle")
    parser.add_argument("--max-duration", type=float, default=300.0,
                        help="flush a flow open longer than this many seconds")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="c2sink")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the sinkhole")
    s.add_argument("--feed", required=True)
    s.add_argument("--host", default="::")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--log", default="events.jsonl")
    s.add_argument("--linger", type=float, default=0.0, help="seconds to hold the socket open before closing")
    s.add_argument("--user", help="drop to this unprivileged user after binding the port")
    s.add_argument("--metrics-host", default="127.0.0.1")
    s.add_argument("--metrics-port", type=int, help="serve Prometheus /metrics and /healthz on this port")
    s.add_argument("--quiet", action="store_true")
    _add_privacy_flags(s)
    _add_writer_flags(s)
    s.set_defaults(func=_serve)

    r = sub.add_parser("report", help="build the per-subscriber report")
    r.add_argument("--log", default="events.jsonl")
    r.add_argument("--json", action="store_true", help="subscriber report as JSON")
    r.add_argument("--health", action="store_true", help="feed-health report (per listed prefix) instead")
    r.add_argument("--feed", help="with --health: seed from the feed so zero-traffic prefixes also appear")
    r.add_argument("--beacons", action="store_true", help="beaconing report (regular call-home patterns) instead")
    r.set_defaults(func=_report)

    i = sub.add_parser("ingest", help="replay a pcap through the analysis pipeline")
    i.add_argument("--pcap", required=True)
    i.add_argument("--feed", required=True)
    i.add_argument("--log", default="events.jsonl")
    i.add_argument("--quiet", action="store_true")
    _add_privacy_flags(i)
    _add_writer_flags(i)
    _add_flow_flags(i)
    i.set_defaults(func=_ingest)

    g = sub.add_parser("rules", help="emit redirect rules for the feed")
    g.add_argument("--feed", required=True)
    g.add_argument("--port", type=int, default=8443)
    g.add_argument("--exabgp", action="store_true")
    g.add_argument("--nh4")
    g.add_argument("--nh6")
    g.add_argument("--community")
    g.set_defaults(func=_rules)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
