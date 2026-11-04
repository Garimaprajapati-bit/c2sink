"""Detect a QUIC Initial packet (RFC 9000 long header).

Detection only: we report that the traffic is QUIC and its version. Extracting
the SNI from a QUIC Initial means deriving the Initial keys from the
Destination Connection ID and decrypting the CRYPTO frames; that's a known,
larger piece of work and is deliberately left as a future step rather than
faked here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class QuicInitial:
    version: int
    dcid: bytes


def parse_initial(payload: bytes) -> Optional[QuicInitial]:
    if len(payload) < 6:
        return None
    first = payload[0]
    # long header has the high bit set; the fixed bit (0x40) is also set
    if not (first & 0x80) or not (first & 0x40):
        return None
    version = struct.unpack_from("!I", payload, 1)[0]
    if version == 0:                     # version negotiation, not an Initial
        return None
    dcid_len = payload[5]
    if dcid_len > 20 or 6 + dcid_len > len(payload):
        return None
    dcid = payload[6:6 + dcid_len]
    # long-header packet type is bits 4-5 of the first byte; 0 == Initial for v1
    pkt_type = (first & 0x30) >> 4
    if version == 0x00000001 and pkt_type != 0:
        return None
    return QuicInitial(version=version, dcid=dcid)
