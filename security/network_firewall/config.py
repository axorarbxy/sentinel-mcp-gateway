"""Validated environment configuration for network firewall enforcement."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

Action = Literal["ALLOW", "BLOCK", "REVIEW"]


def _csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized not in {"1", "true", "yes", "on", "0", "false", "no", "off"}:
        raise ValueError(f"{name} must be a boolean")
    return normalized in {"1", "true", "yes", "on"}


def _ports(name: str, default: str) -> tuple[int, ...]:
    values = _csv(os.getenv(name, default))
    try:
        ports = tuple(sorted({int(value) for value in values}))
    except ValueError as exc:
        raise ValueError(f"{name} must contain comma-separated port numbers") from exc
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError(f"{name} ports must be between 1 and 65535")
    return ports


@dataclass(frozen=True)
class FirewallConfig:
    enabled: bool
    default_action: Action
    allowed_protocols: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    allowed_domains: tuple[str, ...]
    denied_domains: tuple[str, ...]
    block_private: bool
    block_loopback: bool
    block_link_local: bool
    dns_timeout_seconds: float
    connection_timeout_seconds: float
    max_response_bytes: int
    max_connections: int
    connection_limit_window_seconds: int
    cache_ttl_seconds: int

    @classmethod
    def from_env(cls) -> "FirewallConfig":
        default_action = os.getenv("SENTINEL_NETWORK_FIREWALL_DEFAULT_ACTION", "BLOCK").strip().upper()
        if default_action not in {"ALLOW", "BLOCK", "REVIEW"}:
            raise ValueError("SENTINEL_NETWORK_FIREWALL_DEFAULT_ACTION must be ALLOW, BLOCK, or REVIEW")
        try:
            dns_timeout = float(os.getenv("SENTINEL_NETWORK_DNS_TIMEOUT", "3"))
            connection_timeout = float(os.getenv("SENTINEL_NETWORK_CONNECTION_TIMEOUT", "10"))
            max_response_bytes = int(os.getenv("SENTINEL_NETWORK_MAX_RESPONSE_BYTES", "10485760"))
            max_connections = int(os.getenv("SENTINEL_NETWORK_MAX_CONNECTIONS", "100"))
            limit_window = int(os.getenv("SENTINEL_NETWORK_CONNECTION_LIMIT_WINDOW_SECONDS", "60"))
            cache_ttl = int(os.getenv("SENTINEL_NETWORK_DNS_CACHE_TTL_SECONDS", "30"))
        except ValueError as exc:
            raise ValueError("Network firewall numeric configuration is invalid") from exc
        if (
            dns_timeout <= 0 or connection_timeout <= 0 or max_response_bytes < 1
            or max_connections < 1 or limit_window < 1 or cache_ttl < 0
        ):
            raise ValueError("Network firewall timeouts and limits must be positive")

        protocols = tuple(value.lower() for value in _csv(os.getenv("SENTINEL_NETWORK_ALLOWED_PROTOCOLS", "https")))
        if not protocols or any(value not in {"http", "https"} for value in protocols):
            raise ValueError("SENTINEL_NETWORK_ALLOWED_PROTOCOLS may contain only http and https")
        allowed_ports = _ports("SENTINEL_NETWORK_ALLOWED_PORTS", "443")
        if not allowed_ports:
            raise ValueError("SENTINEL_NETWORK_ALLOWED_PORTS must allow at least one port")
        domains = _csv(os.getenv("SENTINEL_NETWORK_ALLOWED_DOMAINS", ""))
        denied_domains = _csv(os.getenv("SENTINEL_NETWORK_DENIED_DOMAINS", ""))

        config = cls(
            enabled=_bool("SENTINEL_NETWORK_FIREWALL_ENABLED", False),
            default_action=default_action,  # type: ignore[arg-type]
            allowed_protocols=protocols,
            allowed_ports=allowed_ports,
            allowed_domains=domains,
            denied_domains=denied_domains,
            block_private=_bool("SENTINEL_NETWORK_BLOCK_PRIVATE", True),
            block_loopback=_bool("SENTINEL_NETWORK_BLOCK_LOOPBACK", True),
            block_link_local=_bool("SENTINEL_NETWORK_BLOCK_LINK_LOCAL", True),
            dns_timeout_seconds=dns_timeout,
            connection_timeout_seconds=connection_timeout,
            max_response_bytes=max_response_bytes,
            max_connections=max_connections,
            connection_limit_window_seconds=limit_window,
            cache_ttl_seconds=cache_ttl,
        )
        for domain in (*config.allowed_domains, *config.denied_domains):
            from .dns_security import normalize_hostname

            normalize_hostname(domain.removeprefix("*."))
        if os.getenv("SENTINEL_ENVIRONMENT", "dev").strip().lower() in {"prod", "production"}:
            if not config.enabled:
                raise ValueError("Network firewall enforcement must be enabled in production")
            if config.default_action != "BLOCK":
                raise ValueError("Network firewall must default to BLOCK in production")
        return config
