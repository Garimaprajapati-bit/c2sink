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
from .report import (build, build_health, load_events, render_health,
                     render_json, render_text)
from .server import Sinkhole


def _serve(args) -> int:
    entries = load_feed(args.feed)
    index = FeedIndex(entries)
    logf = open(args.log, "a", buffering=1, encoding="utf-8")

    def on_event(ev):
        logf.write(ev.to_json_line() + "\n")
        if not args.quiet:
            who = ev.sni or ev.http_host or ev.proto
            print(f"[{ev.proto}] {ev.src_ip} -> {ev.dst_ip}:{ev.dst_port} {who}", file=sys.stderr)

    sink = Sinkhole(index, on_event, linger_seconds=args.linger)

    async def run():
        server = await sink.serve(args.host, args.port)
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
        print(f"c2sink listening on {addrs}; feed entries: {len(index)}", file=sys.stderr)
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    finally:
        logf.close()
    return 0


def _report(args) -> int:
    events = load_events(args.log)
    if args.health:
        print(render_health(build_health(events)))
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


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="c2sink")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the sinkhole")
    s.add_argument("--feed", required=True)
    s.add_argument("--host", default="::")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--log", default="events.jsonl")
    s.add_argument("--linger", type=float, default=0.0, help="seconds to hold the socket open before closing")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=_serve)

    r = sub.add_parser("report", help="build the per-subscriber report")
    r.add_argument("--log", default="events.jsonl")
    r.add_argument("--json", action="store_true", help="subscriber report as JSON")
    r.add_argument("--health", action="store_true", help="feed-health report (per listed destination) instead")
    r.set_defaults(func=_report)

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
