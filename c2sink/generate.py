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
