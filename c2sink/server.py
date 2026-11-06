"""The live sink: one capture source of several.

Accepts TCP connections redirected here for any feed destination, reads only
the first bytes the client sends, records metadata via the shared analysis
layer, and closes without ever sending application data back. It is the minimal
TCP handshake responder: the kernel completes SYN/SYN-ACK/ACK and ACKs the data
so the client sends its ClientHello, and nothing is ever written back. For
offline pcap replay or a live TZSP mirror, see `capture.py`; both produce the
same events through the same `analysis.build_event`.

Original destination recovery:
- Linux REDIRECT: SO_ORIGINAL_DST on the socket gives the real C2 address.
- Otherwise the local accept address is used (fine when the sink host holds
  the announced prefixes directly, e.g. via ExaBGP next-hop = this host).
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import time
from typing import Optional

from .analysis import Event, build_event
from .feed import FeedIndex
from .metrics import Metrics

SO_ORIGINAL_DST = 80          # <linux/netfilter_ipv4.h>
IP6T_SO_ORIGINAL_DST = 80     # <linux/netfilter_ipv6/ip6_tables.h>


def _original_dst(sock: socket.socket) -> Optional[tuple]:
    try:
        family = sock.family
        if family == socket.AF_INET:
            raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port, = struct.unpack_from("!H", raw, 2)
            ip = socket.inet_ntop(socket.AF_INET, raw[4:8])
            return ip, port
        if family == socket.AF_INET6:
            raw = sock.getsockopt(41, IP6T_SO_ORIGINAL_DST, 28)  # 41 = IPPROTO_IPV6
            port, = struct.unpack_from("!H", raw, 2)
            ip = socket.inet_ntop(socket.AF_INET6, raw[8:24])
            return ip, port
    except (OSError, struct.error):
        return None
    return None


class Sinkhole:
    def __init__(self, feed_index: FeedIndex, on_event, read_bytes: int = 16384,
                 read_timeout: float = 5.0, linger_seconds: float = 0.0,
                 pseudonymizer=None, metrics: Metrics = None):
        self.feed = feed_index
        self.on_event = on_event
        self.read_bytes = read_bytes
        self.read_timeout = read_timeout
        self.linger_seconds = linger_seconds
        self.pseudonymizer = pseudonymizer
        self.metrics = metrics or Metrics()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        sock = writer.get_extra_info("socket")
        local = writer.get_extra_info("sockname") or ("?", 0)
        dst = _original_dst(sock) if sock is not None else None
        if dst is None:
            dst = (local[0], local[1])
        data = b""
        try:
            data = await asyncio.wait_for(reader.read(self.read_bytes), timeout=self.read_timeout)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        event = build_event(time.time(), peer[0], peer[1], dst[0], dst[1],
                            data, self.feed, transport="tcp",
                            pseudonymizer=self.pseudonymizer)
        self.metrics.packets += 1            # one observation per connection
        self.metrics.record_event(event.proto)
        try:
            self.on_event(event)
        finally:
            # Never write application data. Optionally hold the socket open a
            # moment so the client thinks it connected, then close.
            if self.linger_seconds:
                try:
                    await asyncio.sleep(self.linger_seconds)
                except asyncio.CancelledError:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, asyncio.TimeoutError):
                pass

    async def serve(self, host: str, port: int) -> asyncio.base_events.Server:
        return await asyncio.start_server(self.handle, host, port, reuse_address=True)


def _no_new_privs() -> None:
    """Best-effort Linux prctl(PR_SET_NO_NEW_PRIVS): once set, a later exec can
    never regain privileges via setuid binaries. Silently skipped off Linux."""
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PR_SET_NO_NEW_PRIVS = 38
        libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    except Exception:
        pass


def drop_privileges(user: str) -> None:
    """Shed root after the privileged socket is bound. The sink needs root only
    to bind a low port and read SO_ORIGINAL_DST on redirected sockets; it must
    not keep it while parsing hostile traffic. Call this right after `serve`,
    before serving. Supplementary groups and the gid are dropped before the uid
    (order matters: the reverse would leave the privilege to undo the change),
    and the drop is verified.

    This is privilege *reduction* in one process. For full privilege
    *separation*, run the collector as a non-root service whose only elevated
    step is setting up the redirect/capture (documented in SECURITY.md), and
    keep the feed and config files read-only to this account."""
    import grp
    import pwd

    if os.getuid() != 0:
        return                               # not root: nothing to drop
    entry = pwd.getpwnam(user)
    os.setgroups([g.gr_gid for g in grp.getgrall() if user in g.gr_mem] or [entry.pw_gid])
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)
    if os.getuid() != entry.pw_uid or os.geteuid() == 0:
        raise PermissionError("failed to drop privileges")
    try:
        os.setuid(0)                         # must fail: prove root is unrecoverable
    except OSError:
        pass
    else:
        raise PermissionError("still able to regain root after drop")
    _no_new_privs()
