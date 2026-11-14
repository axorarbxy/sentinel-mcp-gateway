"""Bounded in-process connection observations and statistics."""

from __future__ import annotations

from collections import Counter, deque
from threading import RLock
from typing import Any


class ConnectionMonitor:
    def __init__(self, *, max_events: int = 10_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be positive")
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._lock = RLock()

    def record(self, event: dict[str, Any]) -> None:
        safe_event = {
            key: event.get(key)
            for key in (
                "agent_id", "destination", "destination_ip", "port", "protocol",
                "timestamp", "decision", "rule_id", "reason", "request_id",
                "outcome", "duration_ms",
            )
        }
        with self._lock:
            self._events.append(safe_event)

    def events(self, *, limit: int = 100, blocked_only: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            values = list(self._events)
        if blocked_only:
            values = [event for event in values if event.get("decision") == "BLOCK"]
        return list(reversed(values[-max(0, min(limit, 1000)):]))

    def statistics(self) -> dict[str, Any]:
        with self._lock:
            values = list(self._events)
        destinations = Counter(
            str(event.get("destination") or "")
            for event in values if event.get("decision") == "BLOCK"
        )
        agents = Counter(str(event.get("agent_id")) for event in values)
        return {
            "observed_connections": len(values),
            "allowed": sum(event.get("decision") == "ALLOW" for event in values),
            "blocked": sum(event.get("decision") == "BLOCK" for event in values),
            "top_blocked_destinations": [
                {"destination": destination, "count": count}
                for destination, count in destinations.most_common(10)
            ],
            "per_agent_activity": dict(agents),
        }
