"""Authenticated smoke test for the live traffic WebSocket."""

import asyncio
import json
import os

import httpx
import pytest
import websockets

GATEWAY_URL = os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8001")
OPERATOR_TOKEN = os.getenv("SENTINEL_OPERATOR_TOKEN", "")
pytestmark = pytest.mark.skipif(
    not OPERATOR_TOKEN,
    reason="Set SENTINEL_OPERATOR_TOKEN to run the authenticated WebSocket smoke test",
)


@pytest.mark.asyncio
async def test_ws():
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{GATEWAY_URL}/auth/ws-ticket",
            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
            timeout=10.0,
        )
    response.raise_for_status()
    ticket = response.json()["ticket"]
    websocket_url = GATEWAY_URL.replace("http://", "ws://").replace("https://", "wss://")
    async with websockets.connect(
        f"{websocket_url}/mcp/ws/traffic",
        subprotocols=["cybereye.v1", f"cybereye-ticket.{ticket}"],
    ) as websocket:
        snapshot = json.loads(await websocket.recv())
        assert snapshot["type"] == "snapshot"
        await websocket.send("ping")
        assert json.loads(await websocket.recv()) == {"type": "pong"}


if __name__ == "__main__":
    if not OPERATOR_TOKEN:
        raise SystemExit("Set SENTINEL_OPERATOR_TOKEN to run the authenticated WebSocket smoke test")
    asyncio.run(test_ws())
