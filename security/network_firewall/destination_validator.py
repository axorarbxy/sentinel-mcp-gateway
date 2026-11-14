"""Strict parsing and validation of outbound upstream URLs."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from .dns_security import normalize_hostname


@dataclass(frozen=True)
class ValidatedDestination:
    original_url: str
    hostname: str
    port: int
    protocol: str


def parse_destination(url: str) -> ValidatedDestination:
    if not isinstance(url, str) or not url or len(url) > 4096:
        raise ValueError("Destination URL is invalid")
    if any(ord(char) < 32 or ord(char) == 127 for char in url) or "\\" in url:
        raise ValueError("Destination URL is invalid")
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.hostname is None
        ):
            raise ValueError("Destination URL is invalid")
        hostname = normalize_hostname(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Destination URL is invalid") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Destination URL port is invalid")
    return ValidatedDestination(url, hostname, port, parsed.scheme.lower())
