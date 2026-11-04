"""Minimal packet parser: a link-layer frame -> transport payload.

Handles the cases a C2 sinkhole sees: Ethernet or raw IP framing, IPv4 and
IPv6 (skipping common v6 extension headers), TCP and UDP. Returns a small
record with the 5-tuple, the payload, and, for TCP, the flags and sequence
number so a flow can be reassembled. Anything it can't parse returns None
rather than raising.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional

# pcap linktypes
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101          # raw IP
LINKTYPE_LINUX_SLL = 113    # Linux cooked capture

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
IPPROTO_TCP = 6
IPPROTO_UDP = 17
# IPv6 extension headers we skip over to reach TCP/UDP
V6_EXT_HEADERS = {0, 43, 44, 60, 51, 50}


@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str          # tcp | udp
    payload: bytes
    tcp_flags: int = 0
    seq: int = 0

    @property
    def syn(self) -> bool:
        return bool(self.tcp_flags & 0x02)


def _l3(data: bytes, ethertype: int) -> Optional[Packet]:
    if ethertype == ETH_P_IP:
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        proto = data[9]
        src = socket.inet_ntop(socket.AF_INET, data[12:16])
        dst = socket.inet_ntop(socket.AF_INET, data[16:20])
        return _l4(data[ihl:], proto, src, dst)
    if ethertype == ETH_P_IPV6:
        if len(data) < 40:
            return None
        proto = data[6]
        src = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
        off = 40
        # walk a few extension headers to reach TCP/UDP
        for _ in range(8):
            if proto in (IPPROTO_TCP, IPPROTO_UDP):
                break
            if proto not in V6_EXT_HEADERS or off + 2 > len(data):
                break
            nxt = data[off]
            ext_len = (data[off + 1] + 1) * 8
            proto = nxt
            off += ext_len
        return _l4(data[off:], proto, src, dst)
    return None


def _l4(data: bytes, proto: int, src: str, dst: str) -> Optional[Packet]:
    if proto == IPPROTO_TCP:
        if len(data) < 20:
            return None
        sport, dport, seq = struct.unpack_from("!HHI", data, 0)
        data_off = (data[12] >> 4) * 4
        flags = data[13]
        if data_off < 20 or len(data) < data_off:
            return None
        return Packet(src, dst, sport, dport, "tcp", data[data_off:], flags, seq)
    if proto == IPPROTO_UDP:
        if len(data) < 8:
            return None
        sport, dport, length = struct.unpack_from("!HHH", data, 0)
        return Packet(src, dst, sport, dport, "udp", data[8:])
    return None


def parse_frame(frame: bytes, linktype: int) -> Optional[Packet]:
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        if ethertype == 0x8100:          # 802.1Q VLAN tag
            if len(frame) < 18:
                return None
            ethertype = struct.unpack_from("!H", frame, 16)[0]
            offset = 18
        return _l3(frame[offset:], ethertype)
    if linktype == LINKTYPE_RAW:
        version = frame[0] >> 4 if frame else 0
        return _l3(frame, ETH_P_IP if version == 4 else ETH_P_IPV6)
    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        ethertype = struct.unpack_from("!H", frame, 14)[0]
        return _l3(frame[16:], ethertype)
    return None
