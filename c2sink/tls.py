"""Parse a TLS ClientHello from the first bytes of a connection.

Returns the server name (SNI), offered versions, cipher suites, extensions and
a JA3 fingerprint (Salesforce's convention: SSLVersion,Ciphers,Extensions,
EllipticCurves,EllipticCurvePointFormats, GREASE values removed, MD5 of that
string). Nothing here decrypts anything: the ClientHello is cleartext.

Truncated input is handled: the parser returns what it could read and sets
``complete`` to False, so a hello split across TCP segments is reported
rather than dropped.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional

HANDSHAKE = 0x16
CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_ALPN = 0x0010

# RFC 8701 GREASE values: must be ignored for fingerprinting.
GREASE = {v for v in range(0x0A0A, 0xFAFB, 0x1010)}


@dataclass
class ClientHello:
    record_version: int
    hello_version: int
    ciphers: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    groups: List[int] = field(default_factory=list)
    point_formats: List[int] = field(default_factory=list)
    supported_versions: List[int] = field(default_factory=list)
    alpn: List[str] = field(default_factory=list)
    sni: Optional[str] = None
    complete: bool = True
    record_length: int = 0

    @property
    def ja3_string(self) -> str:
        def dash(values: List[int]) -> str:
            return "-".join(str(v) for v in values if v not in GREASE)
        return ",".join([
            str(self.hello_version),
            dash(self.ciphers),
            dash(self.extensions),
            dash(self.groups),
            dash(self.point_formats),
        ])

    @property
    def ja3(self) -> str:
        return hashlib.md5(self.ja3_string.encode()).hexdigest()

    @property
    def max_version(self) -> int:
        real = [v for v in self.supported_versions if v not in GREASE]
        return max(real) if real else self.hello_version


class _Reader:
    def __init__(self, data: bytes, start: int = 0, end: Optional[int] = None):
        self.data = data
        self.pos = start
        self.end = len(data) if end is None else min(end, len(data))

    def remaining(self) -> int:
        return self.end - self.pos

    def take(self, n: int) -> bytes:
        if self.pos + n > self.end:
            raise EOFError
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u24(self) -> int:
        b = self.take(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]


def looks_like_tls(data: bytes) -> bool:
    return len(data) >= 6 and data[0] == HANDSHAKE and data[1] == 0x03 and data[5] == CLIENT_HELLO


def parse_client_hello(data: bytes) -> Optional[ClientHello]:
    """Return a ClientHello (possibly partial) or None if this is not TLS."""
    if not looks_like_tls(data):
        return None
    r = _Reader(data)
    try:
        r.u8()                       # content type
        record_version = r.u16()
        record_length = r.u16()
        r.u8()                       # handshake type (checked above)
        hs_length = r.u24()
        hello = ClientHello(record_version=record_version, hello_version=0, record_length=record_length)
        hello.complete = r.remaining() >= hs_length
        hello.hello_version = r.u16()
        r.take(32)                   # random
        r.take(r.u8())               # session id
        cipher_len = r.u16()
        hello.ciphers = [r.u16() for _ in range(cipher_len // 2)]
        r.take(r.u8())               # compression methods
        if r.remaining() < 2:
            return hello
        ext_total = r.u16()
        ext_end = min(r.pos + ext_total, r.end)
        while r.pos + 4 <= ext_end:
            ext_type = r.u16()
            ext_len = r.u16()
            hello.extensions.append(ext_type)
            body = _Reader(data, r.pos, r.pos + ext_len)
            if body.end < r.pos + ext_len:
                hello.complete = False
            try:
                _parse_extension(ext_type, body, hello)
            except EOFError:
                hello.complete = False
            r.pos += ext_len
        if r.pos < ext_total + 2:
            pass
        return hello
    except EOFError:
        hello.complete = False
        return hello


def _parse_extension(ext_type: int, r: _Reader, hello: ClientHello) -> None:
    if ext_type == EXT_SERVER_NAME:
        r.u16()                       # list length
        while r.remaining() >= 3:
            name_type = r.u8()
            name = r.take(r.u16())
            if name_type == 0 and hello.sni is None:
                # SNI is sent as A-label (ASCII) on the wire; decode leniently.
                hello.sni = bytes(name).decode("ascii", errors="replace")
    elif ext_type == EXT_SUPPORTED_GROUPS:
        n = r.u16()
        hello.groups = [r.u16() for _ in range(n // 2)]
    elif ext_type == EXT_EC_POINT_FORMATS:
        n = r.u8()
        hello.point_formats = [r.u8() for _ in range(n)]
    elif ext_type == EXT_SUPPORTED_VERSIONS:
        n = r.u8()
        hello.supported_versions = [r.u16() for _ in range(n // 2)]
    elif ext_type == EXT_ALPN:
        r.u16()
        while r.remaining() >= 1:
            hello.alpn.append(r.take(r.u8()).decode("ascii", errors="replace"))
