"""Distributed per-agent and per-destination connection limits."""

from __future__ import annotations

from typing import Any


class FirewallRateLimiter:
    def __init__(self, state_provider: Any, *, limit: int, window_seconds: int) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("Firewall rate limits must be positive")
        self._state_provider = state_provider
        self._limit = limit
        self._window = window_seconds

    async def allow(self, agent_id: str, destination: str) -> bool:
        state = self._state_provider()
        return await state.consume_rate_limit(
            [
                ("firewall-agent", agent_id),
                ("firewall-destination", destination),
                ("firewall-global", "all"),
            ],
            self._limit,
            self._window,
        )
