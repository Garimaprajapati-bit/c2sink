#!/usr/bin/env bash
# Reproduce the sinkhole end to end using the real production mechanism:
# Linux nat REDIRECT + SO_ORIGINAL_DST. Several "subscribers" (distinct source
# IPs on 127.0.1.0/24) contact several blackholed "C2" destinations
# (127.0.3.0/24, standing in for feed prefixes) on port 443; the kernel
# redirects them to the local sink, which recovers the true C2 address.
#
# Needs root for iptables. Uses only loopback, no external traffic, no malware.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=18443
LOG=examples/repro_events.jsonl
C2NET=127.0.3.0/24
rm -f "$LOG"

cleanup() {
  iptables -t nat -D OUTPUT -p tcp -d "$C2NET" --dport 443 -j REDIRECT --to-ports "$PORT" 2>/dev/null || true
  [ -n "${SINK:-}" ] && kill "$SINK" 2>/dev/null || true
}
trap cleanup EXIT

# feed: the three C2 destinations we will drive traffic to, with labels
cat > examples/repro_feed.txt <<'EOF'
127.0.3.10  ExampleLoaderV4
127.0.3.20  ExampleStealer
127.0.3.30  ExampleProxy
EOF

PYTHONPATH=. python -m c2sink serve --feed examples/repro_feed.txt \
  --host 127.0.0.1 --port "$PORT" --log "$LOG" --quiet &
SINK=$!
sleep 1

iptables -t nat -A OUTPUT -p tcp -d "$C2NET" --dport 443 -j REDIRECT --to-ports "$PORT"

PYTHONPATH=. python3 - <<'PY'
import asyncio
from c2sink.generate import build_client_hello, build_http_get

async def contact(src, dst, payload):
    r, w = await asyncio.open_connection(dst, 443, local_addr=(src, 0))
    w.write(payload); await w.drain()
    try:
        await asyncio.wait_for(r.read(16), timeout=1.0)   # expect nothing back
    except asyncio.TimeoutError:
        pass
    w.close()
    try: await w.wait_closed()
    except Exception: pass

async def main():
    # subscriber A: infected, beacons to the loader C2 twice over TLS
    await contact("127.0.1.11", "127.0.3.10", build_client_hello("api.exampleloader.cc"))
    await contact("127.0.1.11", "127.0.3.10", build_client_hello("api.exampleloader.cc"))
    # subscriber B: talks to the stealer over plaintext HTTP
    await contact("127.0.1.12", "127.0.3.20",
                  build_http_get("panel.examplestealer.su", "/gate.php", "Mozilla/4.0 (compatible)"))
    # subscriber C: proxy malware, raw (no SNI) TLS to the proxy C2
    await contact("127.0.1.13", "127.0.3.30", build_client_hello(None))
    # subscriber A also hits the proxy
    await contact("127.0.1.11", "127.0.3.30", build_client_hello("cdn.exampleproxy.to"))

asyncio.run(main())
PY

sleep 1
kill "$SINK" 2>/dev/null; wait "$SINK" 2>/dev/null || true; SINK=

echo "=== raw events (${LOG}) ==="
cat "$LOG"
echo; echo "=== subscriber report ==="
PYTHONPATH=. python -m c2sink report --log "$LOG"
echo "=== feed-health report ==="
PYTHONPATH=. python -m c2sink report --log "$LOG" --health
