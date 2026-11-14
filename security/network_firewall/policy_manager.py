"""Persistent, versioned administrator-managed firewall rules."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from .rules import NetworkRule, NetworkRuleInput


def list_rules(*, agent_id: int | None = None) -> list[NetworkRule]:
    from database import NetworkFirewallRule, SessionLocal

    db = SessionLocal()
    try:
        query = db.query(NetworkFirewallRule)
        if agent_id is not None:
            query = query.filter(
                (NetworkFirewallRule.agent_id.is_(None))
                | (NetworkFirewallRule.agent_id == agent_id)
            )
        rows = query.order_by(NetworkFirewallRule.priority, NetworkFirewallRule.created_at).all()
        return [_from_row(row) for row in rows]
    finally:
        db.close()


def get_rule(rule_id: str) -> NetworkRule | None:
    from database import NetworkFirewallRule, SessionLocal

    db = SessionLocal()
    try:
        row = db.query(NetworkFirewallRule).filter_by(rule_id=rule_id).first()
        return _from_row(row) if row else None
    finally:
        db.close()


def create_rule(data: NetworkRuleInput, *, actor_id: str | None = None) -> NetworkRule:
    from database import NetworkFirewallRule, NetworkFirewallRuleHistory, SessionLocal

    rule_id = f"NET-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.now(timezone.utc)
    values = data.model_dump()
    db = SessionLocal()
    try:
        row = NetworkFirewallRule(
            rule_id=rule_id,
            enabled=True,
            version=1,
            created_at=now,
            updated_at=now,
            **values,
        )
        db.add(row)
        db.flush()
        db.add(NetworkFirewallRuleHistory(
            rule_id=rule_id,
            version=1,
            action="created",
            actor_id=actor_id,
            snapshot_json=_from_row(row).model_dump_json(),
        ))
        db.commit()
        return _from_row(row)
    finally:
        db.close()


def update_rule(
    rule_id: str, updates: dict, *, actor_id: str | None = None,
) -> NetworkRule | None:
    from database import NetworkFirewallRule, NetworkFirewallRuleHistory, SessionLocal

    db = SessionLocal()
    try:
        row = db.query(NetworkFirewallRule).filter_by(rule_id=rule_id).with_for_update().first()
        if row is None:
            return None
        data = NetworkRuleInput.model_validate({
            "action": updates.get("action", row.action),
            "destination": updates.get("destination", row.destination),
            "priority": updates.get("priority", row.priority),
            "agent_id": updates.get("agent_id", row.agent_id),
            "port": updates.get("port", row.port),
            "protocol": updates.get("protocol", row.protocol),
            "description": updates.get("description", row.description),
        })
        if "enabled" in updates:
            row.enabled = bool(updates["enabled"])
        for key, value in data.model_dump().items():
            setattr(row, key, value)
        row.version += 1
        row.updated_at = datetime.now(timezone.utc)
        db.flush()
        db.add(NetworkFirewallRuleHistory(
            rule_id=rule_id,
            version=row.version,
            action="updated",
            actor_id=actor_id,
            snapshot_json=_from_row(row).model_dump_json(),
        ))
        db.commit()
        return _from_row(row)
    finally:
        db.close()


def delete_rule(rule_id: str, *, actor_id: str | None = None) -> bool:
    from database import NetworkFirewallRule, NetworkFirewallRuleHistory, SessionLocal

    db = SessionLocal()
    try:
        row = db.query(NetworkFirewallRule).filter_by(rule_id=rule_id).first()
        if row is None:
            return False
        db.add(NetworkFirewallRuleHistory(
            rule_id=rule_id,
            version=row.version + 1,
            action="deleted",
            actor_id=actor_id,
            snapshot_json=_from_row(row).model_dump_json(),
        ))
        db.delete(row)
        db.commit()
        return True
    finally:
        db.close()


def list_rule_history(rule_id: str | None = None) -> list[dict]:
    from database import NetworkFirewallRuleHistory, SessionLocal

    db = SessionLocal()
    try:
        query = db.query(NetworkFirewallRuleHistory)
        if rule_id:
            query = query.filter_by(rule_id=rule_id)
        return [
            {
                "rule_id": row.rule_id,
                "version": row.version,
                "action": row.action,
                "actor_id": row.actor_id,
                "snapshot": json.loads(row.snapshot_json),
                "created_at": row.created_at.isoformat(),
            }
            for row in query.order_by(NetworkFirewallRuleHistory.id.desc()).limit(1000).all()
        ]
    finally:
        db.close()


def _from_row(row) -> NetworkRule:
    return NetworkRule(
        rule_id=row.rule_id,
        enabled=row.enabled,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        action=row.action,
        destination=row.destination,
        priority=row.priority,
        agent_id=row.agent_id,
        port=row.port,
        protocol=row.protocol,
        description=row.description or "",
    )


def record_firewall_event(event: dict) -> None:
    """Persist a redacted firewall event and enqueue it in the existing outbox."""
    from database import MCPEventOutbox, NetworkFirewallEvent, SessionLocal

    db = SessionLocal()
    try:
        db.add(NetworkFirewallEvent(
            event_id=event["event_id"],
            agent_id=event.get("agent_id"),
            destination=event["destination"][:253],
            destination_ip=event.get("destination_ip"),
            port=event.get("port"),
            protocol=event.get("protocol"),
            decision=event["decision"],
            rule_id=event.get("rule_id"),
            reason=event["reason"][:500],
            risk=event["risk"],
            outcome=event.get("outcome"),
            duration_ms=event.get("duration_ms"),
            timestamp=datetime.fromisoformat(event["timestamp"]),
        ))
        stream_event = {
            **event,
            "decision": event["decision"].lower(),
        }
        db.add(MCPEventOutbox(
            event_id=event["event_id"],
            event_type="network.firewall.decision",
            schema_version="1.0",
            occurred_at=datetime.fromisoformat(event["timestamp"]).replace(tzinfo=None),
            agent_id=event["agent_id"] if isinstance(event.get("agent_id"), int) else 0,
            decision=event["decision"].lower(),
            severity=event["risk"].lower(),
            payload_json=json.dumps({"type": "network_firewall_event", "data": stream_event}),
            status="pending",
            next_attempt_at=datetime.now(timezone.utc).replace(tzinfo=None),
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
