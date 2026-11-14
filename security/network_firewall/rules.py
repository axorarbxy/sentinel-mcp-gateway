"""Validated network access rule model and destination matching."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .dns_security import normalize_hostname

RuleAction = Literal["ALLOW", "BLOCK", "REVIEW"]


def destination_matches(rule_destination: str, hostname: str, addresses: tuple[str, ...]) -> bool:
    try:
        network = ipaddress.ip_network(rule_destination, strict=False)
    except ValueError:
        try:
            address = ipaddress.ip_address(rule_destination)
        except ValueError:
            try:
                rule_host = normalize_hostname(rule_destination.removeprefix("*."))
            except ValueError:
                return False
            if rule_destination.startswith("*."):
                return hostname != rule_host and hostname.endswith("." + rule_host)
            return hostname == rule_host
        return any(ipaddress.ip_address(candidate) == address for candidate in addresses)
    for candidate in addresses:
        address = ipaddress.ip_address(candidate)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            if network.version == 4 and address.ipv4_mapped in network:
                return True
        elif address.version == network.version and address in network:
            return True
    return False


class NetworkRuleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: RuleAction
    destination: str = Field(min_length=1, max_length=253)
    priority: int = Field(default=100, ge=0, le=10000)
    agent_id: int | None = Field(default=None, ge=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["http", "https"] | None = None
    description: str = Field(default="", max_length=500)

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, value: str) -> str:
        candidate = value.removeprefix("*.")
        if "/" in candidate:
            try:
                return str(ipaddress.ip_network(candidate, strict=False))
            except ValueError as exc:
                raise ValueError("destination must be a hostname, IP address, or CIDR") from exc
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            normalized = normalize_hostname(candidate)
            return "*." + normalized if value.startswith("*.") else normalized


class NetworkRule(NetworkRuleInput):
    rule_id: str
    enabled: bool = True
    version: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
