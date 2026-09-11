"""
WebSocket Test Client
Tests live traffic WebSocket connection
"""

import asyncio
import websockets
import json


async def test_ws():
    uri = "ws://localhost:8001/mcp/ws/traffic"
    try:
        print("Connecting to WebSocket...")
        async with websockets.connect(uri) as ws:
            print("[OK] Connected to WebSocket")

            # Receive initial snapshot
            msg = await ws.recv()
            data = json.loads(msg)
            print(f"[SNAPSHOT] Type: {data['type']}")
            print(f"   Total requests: {data['data']['total_requests']}")
            print(f"   Total blocked: {data['data']['total_blocked']}")
            print(f"   Total anomalies: {data['data']['total_anomalies']}")

            # Send ping
            await ws.send("ping")
            msg = await ws.recv()
            print(f"[PONG] {json.loads(msg)}")

            # Wait for live events for 30 seconds
            print("\n[WAITING] Listening for live events (30 seconds)...")
            print("   Run test_mcp_agent.py in another terminal to send traffic\n")

            try:
                while True:
                    msg = await asyncio.wait_for(ws.recv(), timeout=30.0)
                    data = json.loads(msg)

                    if data.get("type") == "new_request":
                        event = data["data"]
                        status = "[OK]" if event["allowed"] else "[BLOCKED]"
                        print(f"{status} {event['method']} | Agent: {event['agent_id']}")
                        print(f"      Reason: {event['reason'][:80]}")
                        print(f"      Totals: {event['total_requests']} requests, {event['total_blocked']} blocked")
                    elif data.get("type") == "heartbeat":
                        print("[HEARTBEAT] Connection alive")
                    else:
                        print(f"[EVENT] {data}")

            except asyncio.TimeoutError:
                print("\n[TIMEOUT] No events received in 30 seconds")

            print("\n[DONE] WebSocket test complete!")

    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == "__main__":
    asyncio.run(test_ws())