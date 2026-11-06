"""Aggregate the sinkhole event log into a per-subscriber report.

The log is JSONL (one Event per line). The report answers the operator's
actual question: which internal IPs tried to reach a C2, which C2s, when, and
what they revealed (SNI, HTTP host, fingerprint, feed label). No attribution
beyond the feed's own label is attempted.
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from .privacy import sanitize


def _names(values: Iterable[str]) -> str:
    """Join attacker-controlled names for display, stripped of control/escape
    characters so a crafted SNI/Host can't inject terminal sequences."""
    return ", ".join(sorted(sanitize(v) for v in values))


@dataclass
class SubscriberContacts:
    src_ip: str
    first_seen: float
    last_seen: float
    connections: int = 0
    dst_ips: set = field(default_factory=set)
    feed_labels: set = field(default_factory=set)
    snis: set = field(default_factory=set)
    http_hosts: set = field(default_factory=set)
    user_agents: set = field(default_factory=set)
    ja3s: set = field(default_factory=set)
    ja4s: set = field(default_factory=set)
    dns_names: set = field(default_factory=set)

    def observe(self, ev: dict) -> None:
        self.connections += 1
        self.first_seen = min(self.first_seen, ev["ts"])
        self.last_seen = max(self.last_seen, ev["ts"])
        self.dst_ips.add(ev["dst_ip"])
        for field_name, bucket in (
            ("feed_label", self.feed_labels), ("sni", self.snis),
            ("http_host", self.http_hosts), ("user_agent", self.user_agents),
            ("ja3", self.ja3s), ("ja4", self.ja4s), ("dns_qname", self.dns_names),
        ):
            value = ev.get(field_name)
            if value:
                bucket.add(value)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


@dataclass
class Beacon:
    """A regular, automated contact pattern from one source to one C2:
    the hallmark of malware calling home on a timer rather than a human."""
    src_ip: str
    dst_ip: str
    feed_label: Optional[str]
    count: int
    mean_interval: float       # seconds
    jitter: float              # stdev / mean, lower = more regular
    first_seen: float
    last_seen: float


def find_beacons(events: Iterable[dict], min_hits: int = 4,
                 max_jitter: float = 0.25) -> List[Beacon]:
    """Group by (src, dst), look at inter-arrival gaps, and report pairs whose
    timing is regular enough to look automated. Needs at least `min_hits`
    connections so the interval is meaningful."""
    pairs: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
    for ev in events:
        pairs[(ev["src_ip"], ev["dst_ip"])].append(ev)
    beacons: List[Beacon] = []
    for (src, dst), evs in pairs.items():
        if len(evs) < min_hits:
            continue
        ts = sorted(e["ts"] for e in evs)
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.mean(gaps)
        if mean <= 0:
            continue
        jitter = (statistics.pstdev(gaps) / mean) if len(gaps) > 1 else 0.0
        if jitter <= max_jitter:
            beacons.append(Beacon(src, dst, evs[0].get("feed_label"), len(evs),
                                  mean, jitter, ts[0], ts[-1]))
    return sorted(beacons, key=lambda b: b.count, reverse=True)


def render_beacons(beacons: List[Beacon]) -> str:
    if not beacons:
        return "No regular beaconing detected (need >= 4 timed contacts per pair)."
    lines = ["Beaconing (regular automated call-home patterns)",
             "=" * 48, ""]
    for b in beacons:
        lines.append(f"{b.src_ip} -> {b.dst_ip}  [{b.feed_label or 'no-label'}]")
        lines.append(f"  {b.count} contacts, every ~{b.mean_interval:.0f}s "
                     f"(jitter {b.jitter*100:.0f}%)")
        lines.append(f"  {_iso(b.first_seen)} .. {_iso(b.last_seen)}")
        lines.append("")
    return "\n".join(lines)


def load_events(path: str) -> List[dict]:
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def build(events: Iterable[dict]) -> Dict[str, SubscriberContacts]:
    subs: Dict[str, SubscriberContacts] = {}
    for ev in events:
        src = ev["src_ip"]
        if src not in subs:
            subs[src] = SubscriberContacts(src, ev["ts"], ev["ts"])
        subs[src].observe(ev)
    return subs


def render_text(subs: Dict[str, SubscriberContacts]) -> str:
    lines = [
        "Infected-subscriber report (passive sinkhole)",
        "=" * 52,
        f"subscribers that contacted a C2: {len(subs)}",
        "",
    ]
    for sub in sorted(subs.values(), key=lambda s: s.connections, reverse=True):
        lines.append(f"{sub.src_ip}")
        lines.append(f"  connections : {sub.connections}")
        lines.append(f"  window      : {_iso(sub.first_seen)} .. {_iso(sub.last_seen)}")
        lines.append(f"  c2 targets  : {', '.join(sorted(sub.dst_ips))}")
        if sub.feed_labels:
            lines.append(f"  feed labels : {', '.join(sorted(sub.feed_labels))}")
        if sub.snis:
            lines.append(f"  tls sni     : {_names(sub.snis)}")
        if sub.http_hosts:
            lines.append(f"  http host   : {_names(sub.http_hosts)}")
        if sub.user_agents:
            lines.append(f"  user-agent  : {_names(sub.user_agents)}")
        if sub.dns_names:
            lines.append(f"  dns         : {_names(sub.dns_names)}")
        if sub.ja4s:
            lines.append(f"  ja4         : {', '.join(sorted(sub.ja4s))}")
        if sub.ja3s:
            lines.append(f"  ja3         : {', '.join(sorted(sub.ja3s))}")
        lines.append("")
    return "\n".join(lines)


@dataclass
class PrefixHealth:
    """Per feed entry (a prefix, not a single address): how much traffic it is
    catching and from how many distinct sources, when it was last seen, and
    whether the traffic looks like it might be legitimate (a false positive)."""
    prefix: str                       # the feed CIDR, e.g. "203.0.113.0/24"
    feed_label: Optional[str]
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    hits: int = 0
    sources: set = field(default_factory=set)
    dst_ips: set = field(default_factory=set)   # which addresses in the prefix were hit
    snis: set = field(default_factory=set)
    http_hosts: set = field(default_factory=set)
    had_tls_without_sni: bool = False

    def observe(self, ev: dict) -> None:
        self.hits += 1
        self.first_seen = ev["ts"] if self.first_seen is None else min(self.first_seen, ev["ts"])
        self.last_seen = ev["ts"] if self.last_seen is None else max(self.last_seen, ev["ts"])
        self.sources.add(ev["src_ip"])
        self.dst_ips.add(ev["dst_ip"])
        if ev.get("sni"):
            self.snis.add(ev["sni"])
        if ev.get("http_host"):
            self.http_hosts.add(ev["http_host"])
        if ev.get("dns_qname"):
            self.http_hosts.add(ev["dns_qname"])
        if ev.get("proto") == "tls" and not ev.get("sni"):
            self.had_tls_without_sni = True


def build_health(events: Iterable[dict], feed_entries=None) -> Dict[str, PrefixHealth]:
    """Build one record per feed entry, keyed by its prefix. If the feed is
    passed, every listed entry appears, including those with no traffic (so a
    feed operator can see what to prune); traffic is aggregated to the matching
    prefix. Without the feed, records fall back to per-destination grouping."""
    from .feed import FeedIndex

    health: Dict[str, PrefixHealth] = {}
    index = None
    if feed_entries is not None:
        index = FeedIndex(feed_entries)
        for e in feed_entries:
            key = str(e.network)
            health[key] = PrefixHealth(key, e.label)

    for ev in events:
        key = None
        if index is not None:
            match = index.lookup(ev["dst_ip"])
            if match is not None:
                key = str(match.network)
        if key is None:
            key = ev["dst_ip"]      # not in the feed (or no feed given)
            if key not in health:
                health[key] = PrefixHealth(key, ev.get("feed_label"))
        health[key].observe(ev)
    return health


def render_health(health: Dict[str, PrefixHealth], now: Optional[float] = None,
                  recent_hours: float = 24.0) -> str:
    import time as _time
    now = now if now is not None else _time.time()
    with_traffic = sum(1 for h in health.values() if h.hits)
    lines = [
        "Feed-health report (traffic seen per listed prefix)",
        "=" * 52,
        f"listed prefixes: {len(health)}   with traffic: {with_traffic}",
        "",
    ]
    # sort: most hits first, then zero-traffic entries last
    for h in sorted(health.values(), key=lambda x: (x.hits, x.last_seen or 0), reverse=True):
        if not h.hits:
            lines.append(f"{h.prefix}  [{h.feed_label or 'no-label'}]  no-traffic")
            lines.append("  nothing seen in this window (prune candidate)")
            lines.append("")
            continue
        age_h = (now - h.last_seen) / 3600.0
        state = "recently-seen" if age_h <= recent_hours else "quiet"
        lines.append(f"{h.prefix}  [{h.feed_label or 'no-label'}]  {state}")
        lines.append(f"  hits / sources     : {h.hits} / {len(h.sources)}")
        lines.append(f"  last seen          : {_iso(h.last_seen)}  ({age_h:.1f} h ago)")
        if len(h.dst_ips) > 1:
            lines.append(f"  addresses hit      : {', '.join(sorted(h.dst_ips))}")
        names = h.snis | h.http_hosts
        if names:
            lines.append(f"  names seen         : {_names(names)}")
        # possible false positive: many distinct sources all asking for a real
        # looking name suggests legitimate traffic caught by the prefix.
        if len(h.sources) >= 5 and names:
            lines.append("  ** review: many sources + named service; possible false positive **")
        lines.append("")
    return "\n".join(lines)


def render_json(subs: Dict[str, SubscriberContacts]) -> str:
    out = []
    for sub in sorted(subs.values(), key=lambda s: s.connections, reverse=True):
        out.append({
            "src_ip": sub.src_ip,
            "connections": sub.connections,
            "first_seen": _iso(sub.first_seen),
            "last_seen": _iso(sub.last_seen),
            "dst_ips": sorted(sub.dst_ips),
            "feed_labels": sorted(sub.feed_labels),
            "snis": sorted(sub.snis),
            "http_hosts": sorted(sub.http_hosts),
            "user_agents": sorted(sub.user_agents),
            "ja3": sorted(sub.ja3s),
            "ja4": sorted(sub.ja4s),
        })
    return json.dumps(out, indent=2)
