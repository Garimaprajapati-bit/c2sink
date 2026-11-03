import asyncio

import pytest

from c2sink.feed import FeedIndex, parse_feed
from c2sink.generate import build_client_hello, build_http_get, send
from c2sink.report import build, render_text
from c2sink.server import Sinkhole


@pytest.mark.asyncio
async def test_sinkhole_records_and_stays_silent():
    # Feed lookup is by destination; in the loopback test the destination is
    # 127.0.0.1, so register that so the label attaches.
    idx = FeedIndex(parse_feed(["127.0.0.1/32 TestFamily", "::1/128 TestFamily"]))
    events = []
    sink = Sinkhole(idx, events.append, read_timeout=1.0)
    server = await sink.serve("127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        reply_tls = await send("127.0.0.1", port, build_client_hello("c2.evil.example"))
        reply_http = await send("127.0.0.1", port, build_http_get("panel.evil.example", "/gate"))

    # The sink never sends application data back.
    assert reply_tls == b""
    assert reply_http == b""

    assert len(events) == 2
    by_proto = {e.proto: e for e in events}
    assert by_proto["tls"].sni == "c2.evil.example"
    assert by_proto["tls"].ja3
    assert by_proto["tls"].feed_label == "TestFamily"
    assert by_proto["http"].http_host == "panel.evil.example"
    assert by_proto["http"].http_target == "/gate"


@pytest.mark.asyncio
async def test_report_groups_by_source():
    idx = FeedIndex(parse_feed(["127.0.0.1/32 TestFamily"]))
    events = []
    sink = Sinkhole(idx, events.append, read_timeout=1.0)
    server = await sink.serve("127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        for _ in range(3):
            await send("127.0.0.1", port, build_client_hello("c2.evil.example"))

    subs = build(e.__dict__ if not isinstance(e, dict) else e for e in [
        {**vars(ev)} for ev in events
    ])
    assert len(subs) == 1
    sub = next(iter(subs.values()))
    assert sub.connections == 3
    assert "c2.evil.example" in sub.snis
    text = render_text(subs)
    assert "subscribers that contacted a C2: 1" in text
