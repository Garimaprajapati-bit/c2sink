"""Read a classic libpcap file (what `tcpdump -w` writes) and yield frames.

Classic pcap only, both byte orders and microsecond/nanosecond stamps. (pcapng,
which Wireshark writes by default, is a different, block-structured format; a
reader for it can be added, but tcpdump's default output is classic pcap.)
"""

from __future__ import annotations

import struct
from typing import Iterator, Tuple

MAGIC_US = 0xA1B2C3D4        # microsecond timestamps
MAGIC_NS = 0xA1B23C4D        # nanosecond timestamps


def read_pcap(path: str) -> Iterator[Tuple[float, int, bytes]]:
    """Yield (timestamp, linktype, frame_bytes) for each packet."""
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise ValueError("truncated pcap header")
        magic = struct.unpack("<I", header[:4])[0]
        if magic in (MAGIC_US, MAGIC_NS):
            endian, nano = "<", magic == MAGIC_NS
        else:
            magic_be = struct.unpack(">I", header[:4])[0]
            if magic_be in (MAGIC_US, MAGIC_NS):
                endian, nano = ">", magic_be == MAGIC_NS
            else:
                raise ValueError("not a classic pcap file (pcapng is not supported)")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        rec = endian + "IIII"
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                return
            ts_sec, ts_frac, caplen, _origlen = struct.unpack(rec, rh)
            frame = fh.read(caplen)
            if len(frame) < caplen:
                return
            ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
            yield ts, linktype, frame
