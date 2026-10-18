"""Privacy-conscious feature summaries for the live security event stream."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from event_pipeline import EVENT_CONSUMER_GROUP


def _as_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _argument_shape(arguments: Any) -> tuple[int, int]:
    """Return serialized byte size and bounded nesting depth without copying values."""
    try:
        size = len(json.dumps(arguments, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        size = 0

    if not isinstance(arguments, (dict, list)):
        return size, 0
    max_depth = 0
    stack = [(arguments, 1)]
    visited = 0
    while stack and visited < 4096:
        value, depth = stack.pop()
        visited += 1
        max_depth = max(max_depth, depth)
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values() if isinstance(item, (dict, list)))
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value if isinstance(item, (dict, list)))
    return size, max_depth


async def add_observable_features(
    state: Any,
    event: dict[str, Any],
    envelope: dict[str, Any],
    stream_entry_id: str,
) -> dict[str, Any]:
    """Attach six feature families to an event before it reaches live consumers.

    Payload contents are summarized only; raw arguments and credentials are not
    copied into the feature object. Window counts use the shared state store so
    workers calculate the same agent, topic, and graph features.
    """
    if event.get("type") != "mcp_event":
        return event
    data = event.get("data")
    if not isinstance(data, dict):
        return event

    event_id = str(data.get("event_id") or envelope.get("event_id") or "")
    agent_id = data.get("agent_id", envelope.get("agent_id", "unknown"))
    method = str(data.get("method") or "unknown")
    broker_topic = str(envelope.get("topic") or "gateway.events")
    event_type = str(envelope.get("event_type") or event.get("type") or "unknown")
    upstream = data.get("upstream_server")
    tool_name = data.get("tool_name")
    identity_key = str(agent_id)
    topic_key = hashlib.sha256(f"{broker_topic}|{event_type}|{method}".encode("utf-8")).hexdigest()

    agent_events, _ = await state.record_event_window(f"features:agent:{identity_key}", event_id, 60)
    topic_events, _ = await state.record_event_window(f"features:topic:{topic_key}", event_id, 60)

    async def edge_events(edge_type: str, target: Any) -> int:
        if not isinstance(target, str) or not target:
            return 0
        target_hash = hashlib.sha256(target.casefold().encode("utf-8")).hexdigest()
        count, _ = await state.record_event_window(
            f"features:graph:{edge_type}:{identity_key}:{target_hash}", event_id, 300,
        )
        return count

    tool_edge_count = await edge_events("agent-tool", tool_name)
    upstream_edge_count = await edge_events("agent-upstream", upstream)
    topic_edge_count = await edge_events("agent-topic", f"{broker_topic}|{method}")

    occurred_at = _as_utc(envelope.get("occurred_at"))
    delivery_age_ms = None
    if occurred_at is not None:
        delivery_age_ms = max(0, round((datetime.now(timezone.utc) - occurred_at).total_seconds() * 1000))

    arguments = data.get("arguments")
    argument_bytes, argument_depth = _argument_shape(arguments)
    findings = data.get("sqli_findings")
    matched_rules = data.get("matched_rule_ids")
    transport_security = str(envelope.get("security") or "plaintext")
    data["observable_features"] = {
        "identity": {
            "agent_id": agent_id,
            "environment": data.get("environment"),
            "identity_kind": "registered_agent",
        },
        "topics": {
            "broker_topic": broker_topic,
            "event_type": event_type,
            "method": method,
            "upstream": upstream if isinstance(upstream, str) else None,
        },
        "timing": {
            "delivery_age_ms": delivery_age_ms,
            "agent_events_60s": agent_events,
            "topic_events_60s": topic_events,
        },
        "payload_summary": {
            "argument_bytes": argument_bytes,
            "argument_depth": argument_depth,
            "top_level_key_count": len(arguments) if isinstance(arguments, dict) else 0,
            "payload_hash_present": isinstance(data.get("payload_hash"), str) and bool(data.get("payload_hash")),
            "matched_rule_count": len(matched_rules) if isinstance(matched_rules, list) else 0,
            "sqli_finding_count": len(findings) if isinstance(findings, list) else 0,
        },
        "graph_structure": {
            "agent_tool_edge_events_5m": tool_edge_count,
            "agent_upstream_edge_events_5m": upstream_edge_count,
            "agent_topic_edge_events_5m": topic_edge_count,
        },
        "broker_state": {
            "producer_id": envelope.get("producer_id"),
            "consumer_group": EVENT_CONSUMER_GROUP,
            "stream_entry_id": stream_entry_id,
            "delivery_attempts": envelope.get("attempts", 1),
            "event_id_present": bool(event_id),
            "schema_version": envelope.get("schema_version"),
            "transport_security": transport_security,
        },
    }
    return event
