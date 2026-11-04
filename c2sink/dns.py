"""Minimal DNS query parser: pull the first question name out of a datagram.

Enough to recognise DNS-based C2 and record the domain being asked for. Not a
full resolver; it reads the header counts and decodes the first QNAME, with
basic sanity checks so a non-DNS payload returns None instead of garbage.
"""

from __future__ import annotations

import struct
from typing import Optional


def query_name(payload: bytes) -> Optional[str]:
    if len(payload) < 12:
        return None
    qdcount = struct.unpack_from("!H", payload, 4)[0]
    if qdcount < 1:
        return None
    # flags: QR bit (bit 15 of byte 2) should be 0 for a query
    flags = struct.unpack_from("!H", payload, 2)[0]
    if flags & 0x8000:
        return None
    labels = []
    pos = 12
    for _ in range(128):                 # bound the label walk
        if pos >= len(payload):
            return None
        length = payload[pos]
        if length == 0:
            break
        if length & 0xC0:                # compression pointer: not expected in a question
            return None
        pos += 1
        if pos + length > len(payload):
            return None
        label = payload[pos:pos + length]
        try:
            labels.append(label.decode("ascii"))
        except UnicodeDecodeError:
            return None
        pos += length
    if not labels:
        return None
    return ".".join(labels)
