"""Operator API for network firewall policy and decision telemetry."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Security
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func

from auth_routes import require_scopes
import database
from database import NetworkFirewallEvent
from network_firewall.destination_validator import parse_destination
from network_firewall.dns_security import normalize_hostname
from network_firewall.ip_analysis import analyze_ip
from network_firewall.policy_manager import (
    create_rule,
    delete_rule,
    get_rule,
    list_rule_history,
    list_rules,
    update_rule,
)
from network_firewall.rules import NetworkRule, NetworkRuleInput, destination_matches
from network_firewall.service import get_network_firewall

router = APIRouter(
    prefix="/network-firewall",
    tags=["Network firewall"],
)


class NetworkRuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["ALLOW", "BLOCK", "REVIEW"] | None = None
    destination: str | None = Field(default=None, min_length=1, max_length=253)
    priority: int | None = Field(default=None, ge=0, le=10000)
    agent_id: int | None = Field(default=None, ge=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["http", "https"] | None = None
    description: str | None = Field(default=None, max_length=500)
    enabled: bool | None = None


class FirewallSimulation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination: str = Field(min_length=1, max_length=4096)
    agent_id: int | None = Field(default=None, ge=1)
    proposed_rule: NetworkRuleInput | None = None


@router.get("/status")
async def firewall_status(
    _actor: dict = Security(require_scopes, scopes=["gateway:read"]),
) -> dict[str, Any]:
    return await get_network_firewall().get_firewall_status()


@router.get("/rules", response_model=list[NetworkRule])
async def rules(
    agent_id: int | None = Query(default=None, ge=1),
    _actor: dict = Security(require_scopes, scopes=["gateway:read"]),
) -> list[NetworkRule]:
    return list_rules(agent_id=agent_id)


@router.post("/rules", response_model=NetworkRule, status_code=201)
async def add_rule(data: NetworkRuleInput, actor: dict = Security(require_scopes, scopes=["gateway:admin"])):
    existing = list_rules()
    signature = (
        data.action, data.destination, data.agent_id, data.port, data.protocol,
    )
    if any(
        rule.enabled and (
            rule.action, rule.destination, rule.agent_id, rule.port, rule.protocol,
        ) == signature
        for rule in existing
    ):
        raise HTTPException(status_code=409, detail="A matching firewall rule already exists")
    return create_rule(data, actor_id=str(actor.get("sub", "")))


@router.put("/rules/{rule_id}", response_model=NetworkRule)
async def change_rule(
    rule_id: str,
    updates: NetworkRuleUpdate,
    actor: dict = Security(require_scopes, scopes=["gateway:admin"]),
):
    current = get_rule(rule_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    values = current.model_dump()
    values.update(updates.model_dump(exclude_unset=True))
    try:
        candidate = NetworkRuleInput.model_validate({
            key: values[key]
            for key in ("action", "destination", "priority", "agent_id", "port", "protocol", "description")
        })
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    enabled = values.get("enabled", current.enabled)
    if enabled:
        signature = (
            candidate.action, candidate.destination, candidate.agent_id,
            candidate.port, candidate.protocol,
        )
        if any(
            rule.rule_id != rule_id and rule.enabled and (
                rule.action, rule.destination, rule.agent_id, rule.port, rule.protocol,
            ) == signature
            for rule in list_rules()
        ):
            raise HTTPException(status_code=409, detail="A matching firewall rule already exists")
    try:
        updated = update_rule(
            rule_id, updates.model_dump(exclude_unset=True),
            actor_id=str(actor.get("sub", "")),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    return updated


@router.delete("/rules/{rule_id}", status_code=204)
async def remove_rule(
    rule_id: str,
    actor: dict = Security(require_scopes, scopes=["gateway:admin"]),
):
    if not delete_rule(rule_id, actor_id=str(actor.get("sub", ""))):
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    return None


@router.get("/rule-history")
async def rule_history(
    rule_id: str | None = None,
    _actor: dict = Security(require_scopes, scopes=["gateway:read"]),
) -> list[dict[str, Any]]:
    return list_rule_history(rule_id)


@router.get("/events")
async def firewall_events(
    limit: int = Query(default=100, ge=1, le=1000),
    _actor: dict = Security(require_scopes, scopes=["gateway:read"]),
) -> list[dict[str, Any]]:
    return await _read_firewall_events(limit=limit, blocked_only=False)


@router.get("/blocked")
async def blocked_firewall_events(
    limit: int = Query(default=100, ge=1, le=1000),
    _actor: dict = Security(require_scopes, scopes=["gateway:read"]),
) -> list[dict[str, Any]]:
    return await _read_firewall_events(limit=limit, blocked_only=True)


async def _read_firewall_events(*, limit: int, blocked_only: bool) -> list[dict[str, Any]]:
    db = database.SessionLocal()
    try:
        query = db.query(NetworkFirewallEvent)
        if blocked_only:
            query = query.filter(NetworkFirewallEvent.decision == "BLOCK")
        return [
            {
                "event_id": row.event_id,
                "agent_id": row.agent_id,
                "destination": row.destination,
                "destination_ip": row.destination_ip,
                "port": row.port,
                "protocol": row.protocol,
                "decision": row.decision,
                "rule_id": row.rule_id,
                "reason": row.reason,
                "risk": row.risk,
                "outcome": row.outcome,
                "duration_ms": row.duration_ms,
                "timestamp": row.timestamp.isoformat(),
            }
            for row in query.order_by(NetworkFirewallEvent.timestamp.desc()).limit(limit).all()
        ]
    finally:
        db.close()


@router.get("/statistics")
async def firewall_statistics(
    _actor: dict = Security(require_scopes, scopes=["gateway:read"]),
) -> dict[str, Any]:
    db = database.SessionLocal()
    try:
        rows = (
            db.query(NetworkFirewallEvent.agent_id, func.count(NetworkFirewallEvent.id))
            .group_by(NetworkFirewallEvent.agent_id)
            .all()
        )
        top_blocked = (
            db.query(NetworkFirewallEvent.destination, func.count(NetworkFirewallEvent.id))
            .filter(NetworkFirewallEvent.decision == "BLOCK")
            .group_by(NetworkFirewallEvent.destination)
            .order_by(func.count(NetworkFirewallEvent.id).desc())
            .limit(10)
            .all()
        )
        return {
            "observed_connections": db.query(NetworkFirewallEvent).count(),
            "allowed": db.query(NetworkFirewallEvent).filter_by(decision="ALLOW").count(),
            "blocked": db.query(NetworkFirewallEvent).filter_by(decision="BLOCK").count(),
            "top_blocked_destinations": [
                {"destination": destination, "count": count}
                for destination, count in top_blocked
            ],
            "per_agent_activity": {str(agent): count for agent, count in rows},
            "recent": get_network_firewall().monitor.statistics(),
        }
    finally:
        db.close()


@router.post("/test")
async def simulate_policy(
    test: FirewallSimulation,
    _actor: dict = Security(require_scopes, scopes=["gateway:read"]),
) -> dict[str, Any]:
    firewall = get_network_firewall()
    try:
        parsed = parse_destination(test.destination) if "://" in test.destination else None
        hostname = parsed.hostname if parsed else normalize_hostname(test.destination)
        protocol = parsed.protocol if parsed else "https"
        port = (parsed.port if parsed else (443 if protocol == "https" else 80))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    addresses = ()
    try:
        analyze_ip(hostname)
        addresses = (hostname,)
        if firewall._ip_is_prohibited(analyze_ip(hostname)):
            return {"decision": "BLOCK", "reason": "Destination is a prohibited address", "resolved_addresses": []}
    except ValueError:
        pass

    candidates = list_rules(agent_id=test.agent_id)
    if test.proposed_rule:
        candidates.append(NetworkRule(
            rule_id="SIMULATION",
            enabled=True,
            version=1,
            **test.proposed_rule.model_dump(),
        ))
    matching = [
        rule for rule in candidates
        if rule.enabled
        and (rule.agent_id is None or rule.agent_id == test.agent_id)
        and (rule.port is None or rule.port == port)
        and (rule.protocol is None or rule.protocol == protocol)
        and destination_matches(rule.destination, hostname, addresses)
    ]
    denies = [rule for rule in matching if rule.action == "BLOCK"]
    allows = [rule for rule in matching if rule.action == "ALLOW"]
    if denies:
        decision, reason, matched = "BLOCK", "Matched a deny rule", min(denies, key=lambda rule: rule.priority)
    elif allows and addresses:
        decision, reason, matched = "ALLOW", "Matched an allow rule; literal IP passed mandatory checks", min(allows, key=lambda rule: rule.priority)
    elif not addresses:
        decision, reason, matched = "REVIEW", "Simulation does not perform DNS; hostname SSRF safety is unverified", None
    else:
        decision, reason, matched = firewall.config.default_action, "No matching rule; applying default action", None
    if protocol not in firewall.config.allowed_protocols or (
        firewall.config.allowed_ports and port not in firewall.config.allowed_ports
    ):
        decision, reason, matched = "BLOCK", "Protocol or port is not allowed", None
    if any(firewall._domain_matches(rule, hostname) for rule in firewall.config.denied_domains):
        decision, reason, matched = "BLOCK", "Destination is denied by firewall configuration", None
    return {
        "decision": decision,
        "reason": reason,
        "rule_id": matched.rule_id if matched else None,
        "destination": hostname,
        "resolved_addresses": [],
        "network_requests_made": 0,
    }
