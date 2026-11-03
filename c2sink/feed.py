"""Load a C2 feed (IPs or prefixes) and turn it into redirect rules.

The feed format is deliberately minimal so that any blackhole feed can be
exported into it: one IPv4/IPv6 address or CIDR prefix per line, optional
"# comment" and an optional second column with a label (family, source).

    198.51.100.7            # single host
    203.0.113.0/24  Mirai   # prefix with a label
    2001:db8:bad::/48 Emotet
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass(frozen=True)
class FeedEntry:
    network: Network
    label: Optional[str] = None

    @property
    def is_v6(self) -> bool:
        return self.network.version == 6


def parse_feed(lines: Iterable[str]) -> List[FeedEntry]:
    entries: List[FeedEntry] = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        try:
            net = ipaddress.ip_network(parts[0], strict=False)
        except ValueError as exc:
            raise ValueError(f"bad feed line {raw!r}: {exc}") from None
        label = parts[1] if len(parts) > 1 else None
        entries.append(FeedEntry(net, label))
    return entries


def load_feed(path: str) -> List[FeedEntry]:
    with open(path, encoding="utf-8") as fh:
        return parse_feed(fh)


class FeedIndex:
    """Longest-prefix lookup: which feed entry does a destination belong to?"""

    def __init__(self, entries: Iterable[FeedEntry]):
        self._entries = sorted(entries, key=lambda e: e.network.prefixlen, reverse=True)

    def lookup(self, address: str) -> Optional[FeedEntry]:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        for entry in self._entries:
            if ip.version == entry.network.version and ip in entry.network:
                return entry
        return None

    def __len__(self) -> int:
        return len(self._entries)


# --- rule generation ------------------------------------------------------

def iptables_rules(entries: Iterable[FeedEntry], port: int, chain: str = "C2SINK") -> Iterator[str]:
    """Emit nftables/iptables REDIRECT rules sending feed destinations to the
    local sinkhole port. Used on the sink host itself (or on a router that
    DNATs to it). Separate chains for v4 and v6."""
    yield f"iptables -t nat -N {chain} 2>/dev/null || iptables -t nat -F {chain}"
    yield f"ip6tables -t nat -N {chain} 2>/dev/null || ip6tables -t nat -F {chain}"
    for e in entries:
        tool = "ip6tables" if e.is_v6 else "iptables"
        yield f"{tool} -t nat -A {chain} -d {e.network} -p tcp -j REDIRECT --to-ports {port}"
    yield f"iptables -t nat -C PREROUTING -j {chain} 2>/dev/null || iptables -t nat -A PREROUTING -j {chain}"
    yield f"ip6tables -t nat -C PREROUTING -j {chain} 2>/dev/null || ip6tables -t nat -A PREROUTING -j {chain}"


def exabgp_announcements(entries: Iterable[FeedEntry], next_hop_v4: str, next_hop_v6: str,
                         community: Optional[str] = None) -> Iterator[str]:
    """Emit ExaBGP API lines announcing each feed prefix with the sink host as
    next-hop, so the ISP's routers forward C2-bound traffic to the sink instead
    of dropping it. Announce only inside the ISP (no-export)."""
    comm = f" community [{community} no-export]" if community else " community [no-export]"
    for e in entries:
        nh = next_hop_v6 if e.is_v6 else next_hop_v4
        yield f"announce route {e.network} next-hop {nh}{comm}"
