"""Target parsing and strict validation (domain, IP or http(s) URL)."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .models import Target

HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))*$"
)
ILLEGAL = set(" \t\r\n;|&$`<>\"'\\{}()*!")


class TargetError(ValueError):
    pass


def parse_target(raw: str) -> Target:
    raw = (raw or "").strip()
    if not raw:
        raise TargetError("No target given.")
    if any(ch in ILLEGAL for ch in raw):
        raise TargetError("Target contains illegal characters.")
    candidate = raw if "://" in raw else "//" + raw
    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError as exc:
        raise TargetError(f"Invalid target: {exc}")
    if parts.scheme and parts.scheme not in ("http", "https"):
        raise TargetError("Only http:// and https:// targets are supported.")
    if parts.username or parts.password:
        raise TargetError("Credentials inside the target URL are not allowed.")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise TargetError("Could not read a host name from the target.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.match(host):
            raise TargetError(f"'{host}' is not a valid host name.")
    path = parts.path.rstrip("/")
    return Target(raw=raw, host=host, scheme=parts.scheme or "", port=port, path=path)
