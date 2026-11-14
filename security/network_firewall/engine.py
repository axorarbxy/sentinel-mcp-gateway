"""Deterministic network destination policy evaluation."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import FirewallConfig
from .connection_monitor import ConnectionMonitor
from .destination_validator import ValidatedDestination, parse_destination
from .dns_security import SecureDNSResolver, is_metadata_hostname, normalize_hostname
from .ip_analysis import IPAnalysis, analyze_ip
from .policy_manager import list_rules, record_firewall_event
from .rate_limiter import FirewallRateLimiter
from .rules import NetworkRule, destination_matches
from .threat_detection import FirewallThreatDetector

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FirewallRequest:
    agent_id: str
    destination: str
    port: int | None = None
    protocol: str = "https"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FirewallDecision:
    decision: str
    rule_id: str | None
    destination: str
    resolved_addresses: tuple[str, ...]
    agent_id: str
    reason: str
    risk: str
    timestamp: str
    policy_version: int
    event_id: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["resolved_addresses"] = list(self.resolved_addresses)
        return result


class NetworkFirewall:
    def __init__(
        self,
        config: FirewallConfig | None = None,
        *,
        resolver: SecureDNSResolver | None = None,
        rules_provider=list_rules,
        event_recorder=record_firewall_event,
        rate_limiter: FirewallRateLimiter | None = None,
        monitor: ConnectionMonitor | None = None,
        threat_detector: FirewallThreatDetector | None = None,
    ) -> None:
        self.config = config or FirewallConfig.from_env()
        self.resolver = resolver or SecureDNSResolver(
            timeout_seconds=self.config.dns_timeout_seconds,
            cache_ttl_seconds=self.config.cache_ttl_seconds,
        )
        self._rules_provider = rules_provider
        self._event_recorder = event_recorder
        self.rate_limiter = rate_limiter or FirewallRateLimiter(
            self._shared_state,
            limit=self.config.max_connections,
            window_seconds=self.config.connection_limit_window_seconds,
        )
        self.monitor = monitor or ConnectionMonitor()
        self.threat_detector = threat_detector or FirewallThreatDetector()

    @staticmethod
    def _shared_state():
        from shared_state import get_shared_state

        return get_shared_state()

    async def evaluate_request(
        self,
        *,
        agent_id: str | int,
        destination: str,
        port: int | None = None,
        protocol: str = "https",
        metadata: dict[str, Any] | None = None,
        resolve: bool = True,
    ) -> FirewallDecision:
        agent = str(agent_id)
        now = datetime.now(timezone.utc).isoformat()
        event_id = f"net_{uuid.uuid4().hex}"
        normalized_host = "[invalid]"
        addresses: tuple[str, ...] = ()
        selected_port = port
        selected_protocol = protocol.lower()
        parsed: ValidatedDestination | None = None

        try:
            if "://" in destination:
                parsed = parse_destination(destination)
                normalized_host = parsed.hostname
                selected_port = selected_port or parsed.port
                selected_protocol = parsed.protocol
            else:
                normalized_host = normalize_hostname(destination)
            if not self.config.enabled:
                return await self._finish(
                    event_id, agent, normalized_host, selected_port, selected_protocol,
                    (), "ALLOW", None, "Network firewall is explicitly disabled",
                    "low", now, persist=False,
                )
            if selected_protocol not in self.config.allowed_protocols:
                return await self._finish(
                    event_id, agent, normalized_host, selected_port, selected_protocol,
                    (), "BLOCK", "NET-PROTOCOL", "Protocol is not allowed", "high", now,
                )
            if selected_port is None or not 1 <= selected_port <= 65535:
                return await self._finish(
                    event_id, agent, normalized_host, selected_port, selected_protocol,
                    (), "BLOCK", "NET-PORT", "Destination port is invalid", "high", now,
                )
            if self.config.allowed_ports and selected_port not in self.config.allowed_ports:
                return await self._finish(
                    event_id, agent, normalized_host, selected_port, selected_protocol,
                    (), "BLOCK", "NET-PORT", "Destination port is not allowed", "high", now,
                )
            if is_metadata_hostname(normalized_host):
                return await self._finish(
                    event_id, agent, normalized_host, selected_port, selected_protocol,
                    (), "BLOCK", "NET-METADATA", "Cloud metadata destinations are prohibited", "critical", now,
                )

            try:
                if not await self.rate_limiter.allow(agent, normalized_host):
                    return await self._finish(
                        event_id, agent, normalized_host, selected_port, selected_protocol,
                        (), "BLOCK", "NET-RATE-LIMIT", "Network connection rate limit exceeded",
                        "medium", now,
                    )
            except Exception:
                logger.exception("Network firewall rate limiter failed")
                return await self._finish(
                    event_id, agent, normalized_host, selected_port, selected_protocol,
                    (), "BLOCK", "NET-RATE-LIMIT-ERROR", "Firewall rate limiter is unavailable",
                    "high", now, persist=False,
                )

            if resolve:
                addresses = await self.resolver.resolve(normalized_host)
                for address in addresses:
                    analysis = analyze_ip(address)
                    if self._ip_is_prohibited(analysis):
                        return await self._finish(
                            event_id, agent, normalized_host, selected_port, selected_protocol,
                            addresses, "BLOCK", "NET-SSRF", "Destination resolves to a prohibited address",
                            analysis.risk_level, now, destination_ip=address,
                        )
            else:
                try:
                    ipaddress.ip_address(normalized_host)
                    addresses = (normalized_host,)
                    analysis = analyze_ip(normalized_host)
                    if self._ip_is_prohibited(analysis):
                        return await self._finish(
                            event_id, agent, normalized_host, selected_port, selected_protocol,
                            addresses, "BLOCK", "NET-SSRF", "Destination is a prohibited address",
                            analysis.risk_level, now, destination_ip=normalized_host,
                        )
                except ValueError:
                    pass
        except (ValueError, asyncio.TimeoutError) as exc:
            return await self._finish(
                event_id, agent, normalized_host, selected_port, selected_protocol,
                addresses, "BLOCK", "NET-DESTINATION", str(exc), "high", now,
            )

        try:
            rules = self._rules_provider()
            if asyncio.iscoroutine(rules):
                rules = await rules
        except Exception:
            logger.exception("Network firewall policy dependency failed")
            return await self._finish(
                event_id, agent, normalized_host, selected_port, selected_protocol,
                addresses, "BLOCK", "NET-ENGINE-ERROR", "Firewall policy service is unavailable",
                "high", now, persist=False,
            )

        enabled_rules = [rule for rule in rules if rule.enabled]
        matched = [
            rule for rule in enabled_rules
            if (rule.agent_id is None or str(rule.agent_id) == agent)
            and (rule.port is None or rule.port == selected_port)
            and (rule.protocol is None or rule.protocol == selected_protocol)
            and destination_matches(rule.destination, normalized_host, addresses)
        ]
        global_denials = [rule for rule in matched if rule.action == "BLOCK" and rule.agent_id is None]
        denials = global_denials or [rule for rule in matched if rule.action == "BLOCK"]
        if denials:
            rule = min(denials, key=lambda item: (item.priority, item.rule_id))
            return await self._finish(
                event_id, agent, normalized_host, selected_port, selected_protocol,
                addresses, "BLOCK", rule.rule_id, "Destination matched an administrator deny rule",
                "high", now,
            )

        configured_denials = self.config.denied_domains
        if any(self._domain_matches(rule, normalized_host) for rule in configured_denials):
            return await self._finish(
                event_id, agent, normalized_host, selected_port, selected_protocol,
                addresses, "BLOCK", "NET-CONFIG-DENY", "Destination is explicitly denied by configuration",
                "high", now,
            )
        if self.config.allowed_domains and not any(
            self._domain_matches(rule, normalized_host) for rule in self.config.allowed_domains
        ):
            return await self._finish(
                event_id, agent, normalized_host, selected_port, selected_protocol,
                addresses, "BLOCK", "NET-DOMAIN-ALLOWLIST",
                "Destination is not in the configured domain allowlist", "medium", now,
            )
        if self.config.allowed_domains and any(
            self._domain_matches(rule, normalized_host) for rule in self.config.allowed_domains
        ):
            return await self._finish(
                event_id, agent, normalized_host, selected_port, selected_protocol,
                addresses, "ALLOW", "NET-CONFIG-ALLOW",
                "Destination matched the configured domain allowlist", "low", now,
            )

        allows = [rule for rule in matched if rule.action == "ALLOW"]
        reviews = [rule for rule in matched if rule.action == "REVIEW"]
        if allows:
            rule = min(allows, key=lambda item: (item.priority, item.rule_id))
            return await self._finish(
                event_id, agent, normalized_host, selected_port, selected_protocol,
                addresses, "ALLOW", rule.rule_id, "Destination matched an administrator allow rule",
                "low", now,
            )
        if reviews:
            rule = min(reviews, key=lambda item: (item.priority, item.rule_id))
            return await self._finish(
                event_id, agent, normalized_host, selected_port, selected_protocol,
                addresses, "REVIEW", rule.rule_id, "Destination requires administrative review",
                "medium", now,
            )
        if not resolve:
            return await self._finish(
                event_id, agent, normalized_host, selected_port, selected_protocol,
                addresses, "REVIEW", None, "Simulation cannot verify hostname DNS safety",
                "medium", now,
            )
        if self.config.default_action == "ALLOW":
            result = "ALLOW"
        elif self.config.default_action == "REVIEW":
            result = "REVIEW"
        else:
            result = "BLOCK"
        return await self._finish(
            event_id, agent, normalized_host, selected_port, selected_protocol,
            addresses, result, None, "No matching network rule; applying default action",
            "medium" if result != "ALLOW" else "low", now,
        )

    async def check_destination(self, destination: str) -> FirewallDecision:
        return await self.evaluate_request(agent_id="system", destination=destination)

    async def check_ip(self, ip_address: str) -> IPAnalysis:
        return analyze_ip(ip_address)

    async def check_dns(self, hostname: str) -> tuple[str, ...]:
        return await self.resolver.resolve(hostname)

    async def record_connection(self, event: dict[str, Any]) -> None:
        self.monitor.record(event)
        event_id = event.get("event_id")
        if not isinstance(event_id, str):
            return
        try:
            from database import NetworkFirewallEvent, SessionLocal

            db = SessionLocal()
            try:
                row = db.query(NetworkFirewallEvent).filter_by(event_id=event_id).first()
                if row is not None:
                    row.outcome = str(event.get("outcome", ""))[:32] or None
                    duration_ms = event.get("duration_ms")
                    row.duration_ms = float(duration_ms) if isinstance(duration_ms, (int, float)) else None
                    db.commit()
            finally:
                db.close()
        except Exception:
            logger.exception("Failed to update firewall connection outcome event_id=%s", event_id)

    async def get_firewall_status(self) -> dict[str, Any]:
        return {
            "enabled": self.config.enabled,
            "default_action": self.config.default_action,
            "policy_version": self._policy_version(),
            "allowed_protocols": list(self.config.allowed_protocols),
            "allowed_ports": list(self.config.allowed_ports),
        }

    def create_pinned_transport(self, hostname: str, validated_addresses: tuple[str, ...]):
        from .transport import PinnedHTTPXTransport

        if not validated_addresses:
            raise ValueError("A validated DNS address is required")
        return PinnedHTTPXTransport(
            hostname=hostname,
            address=validated_addresses[0],
            timeout_seconds=self.config.connection_timeout_seconds,
            max_connections=self.config.max_connections,
        )

    def _ip_is_prohibited(self, analysis: IPAnalysis) -> bool:
        return (
            analysis.is_loopback and self.config.block_loopback
            or analysis.is_link_local and self.config.block_link_local
            or analysis.is_private_network and self.config.block_private
            or analysis.is_multicast
            or analysis.is_reserved
            or analysis.is_unspecified
            or not analysis.is_global and not (
                analysis.is_private_network and not self.config.block_private
                or analysis.is_loopback and not self.config.block_loopback
                or analysis.is_link_local and not self.config.block_link_local
            )
        )

    @staticmethod
    def _domain_matches(rule: str, hostname: str) -> bool:
        candidate = rule.removeprefix("*.")
        return hostname == candidate or hostname.endswith("." + candidate)

    @staticmethod
    def _policy_version() -> int:
        try:
            rules = list_rules()
            return max((rule.version for rule in rules), default=1)
        except Exception:
            logger.exception("Could not read firewall policy version")
            return 0

    async def _finish(
        self,
        event_id: str,
        agent_id: str,
        destination: str,
        port: int | None,
        protocol: str,
        addresses: tuple[str, ...],
        decision: str,
        rule_id: str | None,
        reason: str,
        risk: str,
        timestamp: str,
        *,
        destination_ip: str | None = None,
        persist: bool = True,
    ) -> FirewallDecision:
        event = {
            "event_id": event_id,
            "agent_id": int(agent_id) if agent_id.isdigit() else agent_id,
            "destination": destination,
            "destination_ip": destination_ip,
            "port": port,
            "protocol": protocol,
            "decision": decision,
            "rule_id": rule_id,
            "reason": reason,
            "risk": risk.upper(),
            "timestamp": timestamp,
            "policy_version": self._policy_version(),
            "request_id": None,
        }
        detections = self.threat_detector.observe(event)
        event["detections"] = detections
        if persist:
            try:
                self._event_recorder(event)
            except Exception:
                logger.exception("Failed to persist firewall decision event_id=%s", event_id)
                if decision == "ALLOW":
                    decision = "BLOCK"
                    reason = "Firewall audit persistence failed; failing closed"
                    rule_id = "NET-AUDIT-ERROR"
                    risk = "high"
                    event.update({
                        "decision": decision,
                        "reason": reason,
                        "rule_id": rule_id,
                        "risk": risk.upper(),
                    })
        self.monitor.record(event)
        return FirewallDecision(
            decision=decision,
            rule_id=rule_id,
            destination=destination,
            resolved_addresses=addresses,
            agent_id=agent_id,
            reason=reason,
            risk=risk,
            timestamp=timestamp,
            policy_version=int(event["policy_version"]),
            event_id=event_id,
        )
