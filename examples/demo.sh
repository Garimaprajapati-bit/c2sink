#!/usr/bin/env bash
# Recording-ready walkthrough of c2sink, paced for a screen/terminal recording.
# Runs the REAL reproduction (nat REDIRECT + SO_ORIGINAL_DST) on loopback.
# Needs root (iptables). No external traffic, no malware.
#
#   asciinema rec demo.cast -c "bash examples/demo.sh"      # record
#   agg demo.cast demo.gif                                  # -> GIF
#   ffmpeg -i demo.gif demo.mp4                             # -> MP4
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=18443
LOG=examples/_demo_events.jsonl
C2NET=127.0.3.0/24
GREEN=$'\033[1;32m'; CYAN=$'\033[1;36m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; R=$'\033[0m'

say()  { printf "%s\n" "${CYAN}# $*${R}"; }
run()  { printf "%s\$ %s%s\n" "$GREEN" "$*" "$R"; eval "$*"; }
beat() { sleep "${1:-1.2}"; }

cleanup() {
  iptables -t nat -D OUTPUT -p tcp -d "$C2NET" --dport 443 -j REDIRECT --to-ports "$PORT" 2>/dev/null || true
  [ -n "${SINK:-}" ] && kill "$SINK" 2>/dev/null || true
  rm -f "$LOG" examples/_demo_feed.txt
}
trap cleanup EXIT

clear
printf "%s\n" "${BOLD}c2sink — passive sinkhole for a BGP C2 blackhole feed${R}"
printf "%s\n\n" "${DIM}an ISP blackholes a C2 prefix; this recovers WHICH customers are infected${R}"
beat 2

say "The feed: the blackholed C2 destinations, with the labels the feed already has."
cat > examples/_demo_feed.txt <<'EOF'
127.0.3.10  ExampleLoader
127.0.3.20  ExampleStealer
127.0.3.30  ExampleProxy
EOF
run "cat examples/_demo_feed.txt"; beat 2

say "Start the sinkhole. It listens, records, and never answers a client."
rm -f "$LOG"
PYTHONPATH=. python -m c2sink serve --feed examples/_demo_feed.txt \
  --host 127.0.0.1 --port "$PORT" --log "$LOG" --quiet &
SINK=$!; sleep 1; beat 1.2

say "Point the blackholed prefixes at the sink (what an edge router/ExaBGP does)."
run "iptables -t nat -A OUTPUT -p tcp -d $C2NET --dport 443 -j REDIRECT --to-ports $PORT"; beat 1.8

say "Now three infected 'subscribers' beacon to those dead C2s (synthetic, loopback only)."
PYTHONPATH=. python3 - <<'PY'
import asyncio
from c2sink.generate import build_client_hello, build_http_get
async def contact(src, dst, payload):
    r, w = await asyncio.open_connection(dst, 443, local_addr=(src, 0))
    w.write(payload); await w.drain()
    try: await asyncio.wait_for(r.read(16), timeout=1.0)   # expect nothing back
    except asyncio.TimeoutError: pass
    w.close()
    try: await w.wait_closed()
    except Exception: pass
async def main():
    await contact("127.0.1.11","127.0.3.10", build_client_hello("api.exampleloader.cc"))
    await contact("127.0.1.11","127.0.3.10", build_client_hello("api.exampleloader.cc"))
    await contact("127.0.1.12","127.0.3.20", build_http_get("panel.examplestealer.su","/gate.php","Mozilla/4.0 (compatible)"))
    await contact("127.0.1.13","127.0.3.30", build_client_hello(None))
    await contact("127.0.1.11","127.0.3.30", build_client_hello("cdn.exampleproxy.to"))
asyncio.run(main())
print("   5 connections sent; each got 0 bytes back from the sink.")
PY
beat 2
sleep 1; kill "$SINK" 2>/dev/null; wait "$SINK" 2>/dev/null || true; SINK=

say "Intelligence 1 — feed health: which listed C2s are still live (what the operator cares about)."
run "PYTHONPATH=. python -m c2sink report --log $LOG --health"; beat 3

say "Intelligence 2 — client fingerprint: JA4 identifies the malware's TLS stack across IPs/SNIs."
run "PYTHONPATH=. python -m c2sink report --log $LOG | grep -A6 127.0.1.13"; beat 3

say "Intelligence 3 — beaconing: regular call-home timing (on a timed sample)."
run "PYTHONPATH=. python -m c2sink report --log examples/beacon_sample.jsonl --beacons"; beat 3

printf "\n%s\n" "${BOLD}The blackhole still drops the traffic. The sinkhole turns it into live feed intelligence: which C2s are active, what the clients are, and how they beacon.${R}"
beat 2.5
