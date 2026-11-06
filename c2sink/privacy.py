"""Privacy and output-safety helpers.

Two concerns are specific to running this inside an ISP:

1. **Subscriber privacy.** The client side of every connection is one of the
   operator's own customers. Where a deployment only needs to improve the feed
   (not to chase an internal infection), the real client address never has to
   touch disk: `Pseudonymizer` replaces it with a salted, keyed token that is
   stable within a dataset (so you can still count distinct sources and spot
   beaconing) but cannot be read back to an address without the secret salt.

   This is pseudonymisation, not anonymisation: the IPv4 space is small enough
   that anyone holding the salt can brute-force the mapping, so the salt is a
   secret and this reduces exposure rather than guaranteeing anonymity. The C2
   (destination) side is deliberately *not* pseudonymised -- it is threat
   intelligence about an attacker, not data about a person.

2. **Output safety.** SNI, HTTP Host/User-Agent and DNS names are attacker
   controlled. The JSONL log is safe (json escapes control bytes), but the
   human-readable reports are printed to a terminal, so a crafted name could
   carry ANSI escape sequences. `sanitize` strips control and escape bytes
   before any such string is displayed.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
from hashlib import sha256
from typing import Optional


class Pseudonymizer:
    """Map a client IP to a stable, non-reversible token using HMAC-SHA256
    keyed with a secret salt. Same IP + same salt -> same token (linkable);
    without the salt the token cannot be turned back into an address."""

    def __init__(self, salt: bytes):
        if not salt:
            raise ValueError("pseudonymisation needs a non-empty salt")
        self._salt = salt

    def ip(self, address: str) -> str:
        try:
            packed = ipaddress.ip_address(address).packed
        except ValueError:
            packed = address.encode("utf-8", "replace")
        token = hmac.new(self._salt, packed, sha256).hexdigest()[:16]
        return f"anon:{token}"


def load_salt(value: Optional[str] = None, path: Optional[str] = None,
              env: str = "C2SINK_SALT") -> Optional[bytes]:
    """Resolve a salt from, in order: an explicit value, a file, or an
    environment variable. Returns None if none is set."""
    if value:
        return value.encode("utf-8")
    if path:
        with open(path, "rb") as fh:
            data = fh.read().strip()
        if not data:
            raise ValueError(f"salt file {path!r} is empty")
        return data
    env_val = os.environ.get(env)
    if env_val:
        return env_val.encode("utf-8")
    return None


# Bytes we never want to send to a terminal unescaped: C0 controls (except the
# harmless space is kept), DEL, and the C1 range that carries ANSI sequences.
_STRIP = {c for c in range(0x00, 0x20)} | {0x7F} | {c for c in range(0x80, 0xA0)}


def sanitize(value: Optional[str], max_len: int = 256) -> Optional[str]:
    """Make an attacker-controlled string safe to print: drop control/escape
    characters and bound the length. Returns the input unchanged when there is
    nothing to strip, None when the input is None."""
    if value is None:
        return None
    cleaned = "".join(ch for ch in value if ord(ch) not in _STRIP)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "...(truncated)"
    return cleaned
