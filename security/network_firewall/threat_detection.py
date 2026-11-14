"""Explainable threshold detections over firewall decisions."""

from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any


class FirewallThreatDetector:
    def __init__(
        self, *, threshold: int = 5, window_seconds: int = 60, max_agents: int = 10_000,
    ) -> None:
        if threshold < 1 or window_seconds < 1 or max_agents < 1:
            raise ValueError("Threat detection limits must be positive")
        self._threshold = threshold
        self._window = timedelta(seconds=window_seconds)
        self._max_agents = max_agents
        self._blocked: OrderedDict[str, deque[datetime]] = OrderedDict()
        self._lock = RLock()

    def observe(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        if event.get("decision") != "BLOCK":
            return []
        agent_id = str(event.get("agent_id", "unknown"))
        now = datetime.now(timezone.utc)
        with self._lock:
            attempts = self._blocked.setdefault(agent_id, deque())
            self._blocked.move_to_end(agent_id)
            while len(self._blocked) > self._max_agents:
                self._blocked.popitem(last=False)
            attempts.append(now)
            cutoff = now - self._window
            while attempts and attempts[0] < cutoff:
                attempts.popleft()
            if len(attempts) != self._threshold:
                return []
        return [{
            "detection_id": "NET-REPEATED-BLOCK",
            "agent_id": agent_id,
            "category": "repeated_unauthorized_connections",
            "severity": "high",
            "evidence": {"blocked_attempts": len(attempts), "window_seconds": int(self._window.total_seconds())},
            "timestamp": now.isoformat(),
            "related_event_ids": [str(event.get("event_id", ""))],
            "recommended_action": "Review the agent's network rules and investigate the attempted destinations.",
        }]
