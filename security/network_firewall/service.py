"""Shared firewall instance and startup configuration validation."""

from __future__ import annotations

from .config import FirewallConfig
from .engine import NetworkFirewall

_firewall: NetworkFirewall | None = None


def validate_firewall_configuration() -> FirewallConfig:
    return FirewallConfig.from_env()


def get_network_firewall() -> NetworkFirewall:
    global _firewall
    if _firewall is None:
        _firewall = NetworkFirewall(FirewallConfig.from_env())
    return _firewall


def reset_network_firewall() -> None:
    global _firewall
    _firewall = None
