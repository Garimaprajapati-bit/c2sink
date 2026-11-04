"""Synthetic traffic generator for testing the sinkhole without real malware.

Opens plain TCP connections to the sink and sends a crafted TLS ClientHello or
HTTP request, so the pipeline (capture -> parse -> report) can be exercised and
regression-tested against known inputs. This is test traffic only: it sends a
ClientHello or a GET line, nothing that controls anything.
"""

from __future__ import annotations

import asyncio
import struct
from typing import List, Optional


def build_client_hello(sni: Optional[str], ciphers: Optional[List[int]] = None,
                       version: int = 0x0303, grease: bool = True) -> bytes:
    """Build a minimal but well-formed TLS 1.2/1.3 ClientHello with an SNI
    extension, suitable for feeding the parser."""
    ciphers = ciphers or [0x1301, 0x1302, 0xc02b, 0xc02f, 0x009e]
    if grease:
        ciphers = [0x0a0a] + ciphers

    def ext(ext_type: int, body: bytes) -> bytes:
        return struct.pack("!HH", ext_type, len(body)) + body

    extensions = b""
    if sni is not None:
        name = sni.encode("idna")
        server_name = struct.pack("!B", 0) + struct.pack("!H", len(name)) + name
        sni_ext = struct.pack("!H", len(server_name)) + server_name
        extensions += ext(0x0000, sni_ext)
    # supported_versions (TLS 1.3 + 1.2)
    sv = struct.pack("!B", 4) + struct.pack("!HH", 0x0304, 0x0303)
    extensions += ext(0x002b, sv)
    # supported_groups
    groups = struct.pack("!H", 4) + struct.pack("!HH", 0x001d, 0x0017)
    extensions += ext(0x000a, groups)
    # ec_point_formats
    extensions += ext(0x000b, struct.pack("!BB", 1, 0))
    # signature_algorithms (a few common ones)
    sigs = [0x0403, 0x0804, 0x0401]
    sig_bytes = b"".join(struct.pack("!H", s) for s in sigs)
    extensions += ext(0x000d, struct.pack("!H", len(sig_bytes)) + sig_bytes)
    # alpn h2,http/1.1
    protos = b"\x02h2\x08http/1.1"
    extensions += ext(0x0010, struct.pack("!H", len(protos)) + protos)

    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    body = struct.pack("!H", version)                        # client version
    body += b"\x00" * 32                                     # random
    body += struct.pack("!B", 0)                             # session id len
    body += struct.pack("!H", len(cipher_bytes)) + cipher_bytes
    body += struct.pack("!BB", 1, 0)                         # compression: null
    body += struct.pack("!H", len(extensions)) + extensions

    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(body))[1:] + body
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record


def build_http_get(host: str, path: str = "/", user_agent: str = "test-bot/1.0") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Accept: */*\r\n\r\n"
    ).encode("latin-1")


async def send(host: str, port: int, payload: bytes, read_reply: bool = True) -> bytes:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(payload)
    await writer.drain()
    reply = b""
    if read_reply:
        try:
            reply = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        except asyncio.TimeoutError:
            pass
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, asyncio.TimeoutError):
        pass
    return reply


# --- packet / pcap builders (for tests and demo captures) ----------------

import socket as _socket


def _ipv4(src, dst, proto, payload):
    import struct
    s = _socket.inet_aton(src); d = _socket.inet_aton(dst)
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, proto, 0) + s + d
    # checksum left 0 (fine for offline parsing)
    return hdr + payload


def tcp_segment(src, dst, sport, dport, seq, payload=b"", flags=0x18):
    """Build an Ethernet+IPv4+TCP frame. flags default PSH|ACK; use 0x02 for SYN."""
    import struct
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, 0, 0) + payload
    ip = _ipv4(src, dst, 6, tcp)
    eth = b"\x00\x00\x00\x00\x00\x02" + b"\x00\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + ip


def udp_datagram(src, dst, sport, dport, payload=b""):
    import struct
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = _ipv4(src, dst, 17, udp)
    eth = b"\x00\x00\x00\x00\x00\x02" + b"\x00\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + ip


def write_pcap(path, frames, linktype=1):
    """frames: iterable of (ts, frame_bytes). Writes a classic microsecond pcap."""
    import struct
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, frame in frames:
            sec = int(ts); usec = int((ts - sec) * 1e6)
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


def dns_query(qname):
    """A minimal DNS A-query datagram payload for `qname`."""
    import struct
    q = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)
