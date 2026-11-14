"""Asynchronous DNS resolution with bounded caching and injectable resolvers."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable

Resolver = Callable[[str], Awaitable[Iterable[str]]]
_BLOCKED_HOSTS = {
    "metadata",
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data",
}


def normalize_hostname(hostname: str) -> str:
    if not isinstance(hostname, str) or not hostname or len(hostname) > 253:
        raise ValueError("Destination hostname is invalid")
    if any(ord(char) < 33 or ord(char) == 127 for char in hostname) or "%" in hostname:
        raise ValueError("Destination hostname is invalid")
    value = hostname[:-1] if hostname.endswith(".") else hostname
    if value.endswith("."):
        raise ValueError("Destination hostname is invalid")
    if not value:
        raise ValueError("Destination hostname is invalid")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Destination hostname is invalid") from exc
    labels = normalized.split(".")
    if any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        or not all(char.isalnum() or char == "-" for char in label)
        for label in labels
    ):
        raise ValueError("Destination hostname is invalid")
    return normalized


def is_metadata_hostname(hostname: str) -> bool:
    return hostname in _BLOCKED_HOSTS or hostname.endswith(".metadata.google.internal")


async def _system_resolver(hostname: str) -> Iterable[str]:
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    return {record[4][0] for record in records}


class SecureDNSResolver:
    def __init__(
        self,
        resolver: Resolver | None = None,
        *,
        timeout_seconds: float = 3,
        cache_ttl_seconds: int = 30,
        max_entries: int = 512,
    ) -> None:
        if timeout_seconds <= 0 or cache_ttl_seconds < 0 or max_entries < 1:
            raise ValueError("DNS resolver limits are invalid")
        self._resolver = resolver or _system_resolver
        self._timeout = timeout_seconds
        self._ttl = cache_ttl_seconds
        self._max_entries = max_entries
        self._cache: OrderedDict[str, tuple[float, tuple[str, ...]]] = OrderedDict()
        self._locks: dict[str, asyncio.Lock] = {}
        self._lock_users: dict[str, int] = {}

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        normalized = normalize_hostname(hostname)
        try:
            ipaddress.ip_address(normalized)
            return (normalized,)
        except ValueError:
            pass
        if is_metadata_hostname(normalized):
            raise ValueError("Cloud metadata destinations are prohibited")

        now = time.monotonic()
        cached = self._cache.get(normalized)
        if cached and cached[0] > now:
            self._cache.move_to_end(normalized)
            return cached[1]
        lock = self._locks.setdefault(normalized, asyncio.Lock())
        self._lock_users[normalized] = self._lock_users.get(normalized, 0) + 1
        try:
            async with lock:
                cached = self._cache.get(normalized)
                if cached and cached[0] > time.monotonic():
                    self._cache.move_to_end(normalized)
                    return cached[1]
                try:
                    records = await asyncio.wait_for(self._resolver(normalized), timeout=self._timeout)
                except (asyncio.TimeoutError, OSError, socket.gaierror) as exc:
                    raise ValueError("Destination DNS resolution failed") from exc
                addresses: set[str] = set()
                try:
                    for record in records:
                        addresses.add(str(ipaddress.ip_address(record)))
                except ValueError as exc:
                    raise ValueError("DNS returned a malformed address") from exc
                if not addresses:
                    raise ValueError("Destination has no A or AAAA records")
                result = tuple(sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, item)))
                if self._ttl:
                    self._cache[normalized] = (time.monotonic() + self._ttl, result)
                    self._cache.move_to_end(normalized)
                    while len(self._cache) > self._max_entries:
                        self._cache.popitem(last=False)
                return result
        finally:
            users = self._lock_users[normalized] - 1
            if users:
                self._lock_users[normalized] = users
            else:
                self._lock_users.pop(normalized, None)
                if self._locks.get(normalized) is lock:
                    self._locks.pop(normalized, None)
