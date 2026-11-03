"""Parse the request line and headers of a plaintext HTTP request."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ", b"PATCH ")


@dataclass
class HttpRequest:
    method: str
    target: str
    version: str
    headers: Dict[str, str] = field(default_factory=dict)
    complete: bool = True

    @property
    def host(self) -> Optional[str]:
        return self.headers.get("host")

    @property
    def user_agent(self) -> Optional[str]:
        return self.headers.get("user-agent")


def looks_like_http(data: bytes) -> bool:
    return data.startswith(METHODS)


def parse_request(data: bytes) -> Optional[HttpRequest]:
    if not looks_like_http(data):
        return None
    head, sep, _ = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(" ", 2)
    if len(parts) != 3:
        return None
    req = HttpRequest(method=parts[0], target=parts[1], version=parts[2], complete=bool(sep))
    for line in lines[1:]:
        name, colon, value = line.decode("latin-1").partition(":")
        if colon:
            req.headers[name.strip().lower()] = value.strip()
    return req
