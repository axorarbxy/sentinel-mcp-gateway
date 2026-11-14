"""IP address parsing and policy-relevant address classification."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass

_IPV4_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_IPV6_PRIVATE_NETWORKS = (ipaddress.ip_network("fc00::/7"),)


@dataclass(frozen=True)
class IPAnalysis:
    address: str
    version: int
    is_private: bool
    is_loopback: bool
    is_link_local: bool
    is_multicast: bool
    is_reserved: bool
    is_unspecified: bool
    is_global: bool
    is_private_network: bool
    risk_level: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def analyze_ip(value: str) -> IPAnalysis:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Destination is not a valid IP address") from exc

    effective = None
    if isinstance(address, ipaddress.IPv6Address):
        effective = address.ipv4_mapped or address.sixtofour
        if effective is None and address.teredo is not None:
            effective = address.teredo[1]
        nat64_prefix = ipaddress.ip_network("64:ff9b::/96")
        if effective is None and address in nat64_prefix:
            effective = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    classified = effective or address
    private_networks = _IPV4_PRIVATE_NETWORKS if classified.version == 4 else _IPV6_PRIVATE_NETWORKS
    is_private_network = any(classified in network for network in private_networks)
    prohibited = (
        classified.is_loopback
        or classified.is_private
        or classified.is_link_local
        or classified.is_multicast
        or classified.is_reserved
        or classified.is_unspecified
        or not classified.is_global
    )
    risk = "critical" if (
        classified.is_loopback or classified.is_link_local
        or classified.is_unspecified or classified.is_multicast
    ) else "high" if prohibited else "low"
    return IPAnalysis(
        address=str(address),
        version=address.version,
        is_private=classified.is_private,
        is_loopback=classified.is_loopback,
        is_link_local=classified.is_link_local,
        is_multicast=classified.is_multicast,
        is_reserved=classified.is_reserved,
        is_unspecified=classified.is_unspecified,
        is_global=classified.is_global,
        is_private_network=is_private_network,
        risk_level=risk,
    )
