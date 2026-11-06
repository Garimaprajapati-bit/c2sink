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
EXT_SIGNATURE_ALGORITHMS = 0x000D

# RFC 8701 GREASE values: must be ignored for fingerprinting.
GREASE = {v for v in range(0x0A0A, 0xFAFB, 0x1010)}

# TLS version code -> JA4 two-char label.
_JA4_VERSION = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}


@dataclass
class ClientHello:
    record_version: int
    hello_version: int
    ciphers: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    groups: List[int] = field(default_factory=list)
    point_formats: List[int] = field(default_factory=list)
    supported_versions: List[int] = field(default_factory=list)
    sig_algs: List[int] = field(default_factory=list)
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

    @property
    def ja4(self) -> str:
        """JA4 TLS client fingerprint (FoxIO spec).

        ja4_a _ ja4_b _ ja4_c
          a: proto(t) + tls-version + d|i(SNI) + 2-digit cipher count +
             2-digit extension count + 2 chars from the first ALPN
          b: first 12 hex of sha256 of the sorted GREASE-free cipher list
          c: first 12 hex of sha256 of the sorted GREASE-free extension list
             (SNI and ALPN removed) + "_" + signature algorithms in order
        """
        ciphers = [c for c in self.ciphers if c not in GREASE]
        exts = [e for e in self.extensions if e not in GREASE]
        sigs = [s for s in self.sig_algs if s not in GREASE]

        ver = _JA4_VERSION.get(self.max_version, "00")
        sni_flag = "d" if self.sni else "i"
        nc = f"{min(len(ciphers), 99):02d}"
        ne = f"{min(len(exts), 99):02d}"
        if self.alpn and self.alpn[0]:
            a = self.alpn[0]
            alpn = (a[0] + a[-1]) if a.isascii() else "99"
        else:
            alpn = "00"
        ja4_a = f"t{ver}{sni_flag}{nc}{ne}{alpn}"

        def hex12(values) -> str:
            if not values:
                return "000000000000"
            joined = ",".join(f"{v:04x}" for v in values)
            return hashlib.sha256(joined.encode()).hexdigest()[:12]

        ja4_b = hex12(sorted(ciphers))
        ext_for_c = sorted(e for e in exts if e not in (EXT_SERVER_NAME, EXT_ALPN))
        if not ext_for_c and not sigs:
            ja4_c = "000000000000"
        else:
            s = ",".join(f"{v:04x}" for v in ext_for_c) + "_" + ",".join(f"{v:04x}" for v in sigs)
            ja4_c = hashlib.sha256(s.encode()).hexdigest()[:12]
        return f"{ja4_a}_{ja4_b}_{ja4_c}"


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
    # Create the record up front so a truncation inside the fixed header (the
    # input can be as short as 6 bytes) still returns a partial hello rather
    # than leaving `hello` unbound when the EOFError handler runs.
    hello = ClientHello(record_version=0, hello_version=0, complete=False)
    try:
        r.u8()                       # content type
        hello.record_version = r.u16()
        hello.record_length = r.u16()
        r.u8()                       # handshake type (checked above)
        hs_length = r.u24()
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
            hello.alpn.append(bytes(r.take(r.u8())).decode("ascii", errors="replace"))
    elif ext_type == EXT_SIGNATURE_ALGORITHMS:
        n = r.u16()
        hello.sig_algs = [r.u16() for _ in range(n // 2)]
