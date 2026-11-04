"""TZSP (TaZmen Sniffer Protocol) decapsulation.

Routers such as MikroTik can mirror captured traffic and stream it, each packet
wrapped in TZSP over UDP (default port 37008), to a collector. This strips the
TZSP header and returns the encapsulated frame so it can go through the same
packet parser as a pcap. Decapsulation only; nothing here talks back.
"""

from __future__ import annotations

import struct
from typing import Optional, Tuple

from .packet import LINKTYPE_ETHERNET

TZSP_TAG_PADDING = 0x00
TZSP_TAG_END = 0x01
# TZSP encapsulated-protocol field: 1 == Ethernet
TZSP_PROTO_ETHERNET = 0x01


def decapsulate(data: bytes) -> Optional[Tuple[int, bytes]]:
    """Return (linktype, inner_frame) or None if this is not TZSP we handle."""
    if len(data) < 4:
        return None
    version, _type, encap = data[0], data[1], struct.unpack_from("!H", data, 2)[0]
    if version != 1 or encap != TZSP_PROTO_ETHERNET:
        return None
    pos = 4
    while pos < len(data):
        tag = data[pos]
        if tag == TZSP_TAG_END:
            pos += 1
            break
        if tag == TZSP_TAG_PADDING:
            pos += 1
            continue
        if pos + 1 >= len(data):
            return None
        tag_len = data[pos + 1]
        pos += 2 + tag_len
    if pos > len(data):
        return None
    return LINKTYPE_ETHERNET, data[pos:]
