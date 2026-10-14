import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

import gateway
import mcp_interception
from database import MCPRequestEvent
from monitor import BehavioralMonitor
from test_api_key_auth import (
    add_agent,
    gateway_client,
    operator_token,
    set_fake_upstream,
)


def message(method, params=None, request_id=1):
    result = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        result["id"] = request_id
    if params is not None:
        result["params"] = params
    return result


def agent_headers(key):
    return {"Authorization": f"Bearer {key}"}


def operator_headers():
    return {"Authorization": f"Bearer {operator_token()}"}


def test_tools_list_filters_and_persists_redacted_queryable_event(gateway_client, monkeypatch, caplog):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    calls = []

    async def upstream(request):
        calls.append(request)
        payload = json.loads(request.content)
        assert "authorization" not in request.headers
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"jsonrpc": "2.0", "id": payload["id"], "result": {
                "tools": [
                    {"name": "filesystem.read", "description": "read", "inputSchema": {"type": "object"}},
                    {"name": "dangerous.delete", "description": "delete", "inputSchema": {"type": "object"}},
                ],
            }},
        )

    set_fake_upstream(monkeypatch, upstream)
    response = client.post(
        "/mcp/proxy",
        headers=agent_headers(key),
        json=message("tools/list"),
    )
    assert response.status_code == 200
    assert [tool["name"] for tool in response.json()["result"]["tools"]] == ["filesystem.read"]
    assert len(calls) == 1

    events = client.get("/mcp/events", headers=operator_headers(), params={"agent_id": agent_id})
    assert events.status_code == 200
    assert events.json()["events"][0]["method"] == "tools/list"
    assert events.json()["events"][0]["decision"] == "allow"
    assert events.json()["events"][0]["rule_risk_score"] == 0.0
    assert events.json()["events"][0]["decision_source"] == "rule"
    assert events.json()["events"][0]["ml_score"] is None
    db = session_factory()
    assert db.query(MCPRequestEvent).filter_by(agent_id=agent_id, method="tools/list").count() == 1
    db.close()
    assert key not in caplog.text


def test_proxy_traffic_trains_per_agent_behavioral_model(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    monitor = BehavioralMonitor(window_size=100, contamination=0.1)
    monkeypatch.setattr(gateway, "behavioral_monitor", monitor)

    for request_id in range(20):
        response = client.post(
            "/mcp/proxy",
            headers=agent_headers(key),
            json=message(
                "tools/call",
                {
                    "name": "filesystem.read",
                    "arguments": {"path": f"/home/user/file-{request_id}.txt"},
                },
                request_id=request_id,
            ),
        )
        assert response.status_code == 200

    assert monitor.get_stats()["agents_monitored"] == 1
    assert str(agent_id) in monitor.models


def test_stats_and_behavioral_models_restore_from_persisted_events(gateway_client):
    client, session_factory = gateway_client
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    db = session_factory()
    try:
        for index in range(20):
            blocked = index == 0
            db.add(MCPRequestEvent(
                event_id=f"persisted-event-{index}",
                timestamp=now - timedelta(minutes=19 - index),
                agent_id=9001,
                agent_name="persisted-agent",
                method="tools/call",
                decision="block" if blocked else "allow",
                decision_reason="SQL injection indicator" if blocked else "",
                matched_rule_ids='["SQLI-003"]' if blocked else "[]",
                sqli_findings_json='[{"id":"SQLI-003"}]' if blocked else "[]",
                payload_json=json.dumps({
                    "arguments": {"path": f"/home/user/file-{index}.txt"},
                    "behavioral_anomaly": blocked,
                }),
            ))
        db.commit()
    finally:
        db.close()

    gateway.restore_behavioral_models()
    assert "9001" in gateway.behavioral_monitor.models

    stats_response = client.get("/stats", headers=operator_headers())
    assert stats_response.status_code == 200
    stats = stats_response.json()
    assert stats["total_requests"] == 20
    assert stats["blocked"] == 1
    assert stats["anomaly_alerts"] == 1
    assert stats["ml_models"] == 1
    assert stats["detection_categories"]["SQL injection"] == 1
    assert stats["detection_categories"]["Behavioral anomalies"] == 1
    assert sum(bucket["events"] for bucket in stats["traffic_by_hour"]) == 20


def test_agent_request_is_pushed_to_authenticated_live_dashboard(gateway_client):
    client, _ = gateway_client
    key, _, agent_id = add_agent(gateway_client[1])
    ticket_response = client.post("/auth/ws-ticket", headers=operator_headers())
    assert ticket_response.status_code == 200
    ticket = ticket_response.json()["ticket"]

    with client.websocket_connect(
        "/mcp/ws/traffic",
        subprotocols=["cybereye.v1", f"cybereye-ticket.{ticket}"],
        headers={"host": "localhost"},
    ) as websocket:
        assert json.loads(websocket.receive_text())["type"] == "snapshot"
        response = client.post(
            "/mcp/proxy",
            headers=agent_headers(key),
            json=message("tools/call", {"name": "shell.exec", "arguments": {}}),
        )
        assert response.status_code == 200
        assert response.json()["error"]["code"] == -32000

        live_message = json.loads(websocket.receive_text())

    assert live_message["type"] == "mcp_event"
    assert live_message["data"]["agent_id"] == agent_id
    assert live_message["data"]["agent_name"] == "test-agent"
    assert live_message["data"]["method"] == "tools/call"
    assert live_message["data"]["decision"] == "block"
    assert isinstance(live_message["data"]["rule_risk_score"], (float, int))
    assert live_message["data"]["decision_source"] == "rule"


def test_behavioral_anomaly_is_included_in_live_dashboard_event(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    monkeypatch.setattr(gateway.behavioral_monitor, "add_request", lambda agent_id, request: (True, {}))
    ticket_response = client.post("/auth/ws-ticket", headers=operator_headers())
    assert ticket_response.status_code == 200
    ticket = ticket_response.json()["ticket"]

    with client.websocket_connect(
        "/mcp/ws/traffic",
        subprotocols=["cybereye.v1", f"cybereye-ticket.{ticket}"],
        headers={"host": "localhost"},
    ) as websocket:
        assert json.loads(websocket.receive_text())["type"] == "snapshot"
        response = client.post(
            "/mcp/proxy",
            headers=agent_headers(key),
            json=message(
                "tools/call",
                {"name": "filesystem.read", "arguments": {"path": "/home/user/readme.txt"}},
            ),
        )
        assert response.status_code == 200
        live_message = json.loads(websocket.receive_text())

    assert live_message["type"] == "mcp_event"
    assert live_message["data"]["agent_id"] == agent_id
    assert live_message["data"]["ml_anomaly"] is True
    persisted = client.get("/mcp/events", headers=operator_headers(), params={"agent_id": agent_id})
    assert persisted.status_code == 200
    assert persisted.json()["events"][0]["ml_anomaly"] is True


def test_cors_allows_mcp_session_header(gateway_client):
    client, _ = gateway_client
    response = client.options(
        "/mcp/proxy",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type,mcp-session-id",
        },
    )

    assert response.status_code == 200
    assert "mcp-session-id" in response.headers["access-control-allow-headers"].lower()


def test_disallowed_tool_call_is_blocked_before_upstream(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, _ = add_agent(session_factory)
    calls = []

    async def upstream(request):
        calls.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    set_fake_upstream(monkeypatch, upstream)
    response = client.post(
        "/mcp/proxy",
        headers=agent_headers(key),
        json=message("tools/call", {"name": "shell.exec", "arguments": {}}),
    )
    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32000
    assert "allowed_tools" in response.json()["error"]["message"]
    assert calls == []


def test_batch_mixed_decisions_do_not_smuggle_blocked_tool(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, _ = add_agent(session_factory)
    db = session_factory()
    from database import MCPAgent

    db.query(MCPAgent).filter_by(name="test-agent").update({
        MCPAgent.allowed_tools: json.dumps(["safe"]),
    })
    db.commit()
    db.close()
    calls = []

    async def upstream(request):
        payload = json.loads(request.content)
        calls.append(payload["params"]["name"])
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}},
        )

    set_fake_upstream(monkeypatch, upstream)
    response = client.post(
        "/mcp/proxy",
        headers=agent_headers(key),
        json=[
            message("tools/call", {"name": "safe", "arguments": {}}, 1),
            message("tools/call", {"name": "blocked", "arguments": {}}, 2),
        ],
    )
    assert response.status_code == 200
    replies = {item["id"]: item for item in response.json()}
    assert replies[1]["result"]["ok"] is True
    assert replies[2]["error"]["code"] == -32000
    assert calls == ["safe"]
    db = session_factory()
    assert db.query(MCPRequestEvent).filter(MCPRequestEvent.method == "tools/call").count() == 2
    db.close()


@pytest.mark.parametrize("raw_body", [
    b'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}',
    b'{"jsonrpc":"1.0","id":1,"method":"tools/list"}',
    b'{"jsonrpc":"2.0","method":"tools/list","params":"not-an-object"}',
    b'{"jsonrpc":"2.0","id":null,"method":"tools/list"}',
])
def test_malformed_or_ambiguous_jsonrpc_is_rejected(gateway_client, raw_body):
    client, _ = gateway_client
    key, _, _ = add_agent(gateway_client[1])
    response = client.post(
        "/mcp/proxy",
        headers={**agent_headers(key), "Content-Type": "application/json"},
        content=raw_body,
    )
    assert response.status_code == 400
    assert "error" in response.json()


def test_malformed_json_uses_jsonrpc_parse_error(gateway_client):
    client, session_factory = gateway_client
    key, _, _ = add_agent(session_factory)
    response = client.post(
        "/mcp/proxy",
        headers={**agent_headers(key), "Content-Type": "application/json"},
        content=b'{"jsonrpc":',
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32700


def test_client_must_accept_json_and_sse(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, _ = add_agent(session_factory)
    calls = []

    async def upstream(request):
        calls.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    set_fake_upstream(monkeypatch, upstream)
    response = client.post(
        "/mcp/proxy",
        headers={**agent_headers(key), "Accept": "application/json"},
        json=message("tools/list"),
    )
    assert response.status_code == 406
    assert calls == []


def test_evaluator_timeout_fails_closed(gateway_client, monkeypatch):
    client, _ = gateway_client
    key, _, _ = add_agent(gateway_client[1])
    calls = []

    async def upstream(request):
        calls.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    async def slow_decision(event, agent):
        await asyncio.sleep(0.1)
        return mcp_interception.Decision("allow", "late allow")

    set_fake_upstream(monkeypatch, upstream)
    monkeypatch.setattr(mcp_interception, "decision_hook", slow_decision)
    monkeypatch.setattr(mcp_interception, "EVALUATOR_TIMEOUT_SECONDS", 0.01)
    response = client.post("/mcp/proxy", headers=agent_headers(key), json=message("tools/list"))
    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32000
    assert "timed out" in response.json()["error"]["message"]
    assert calls == []


def test_redaction_applies_to_persisted_and_streamed_event_payload(gateway_client, monkeypatch, caplog):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory, allowed_tools="[]")
    sensitive = "not-for-logs-cye_test_aabbccdd11223344_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
    upstream_auth = []

    async def upstream(request):
        payload = json.loads(request.content)
        upstream_auth.append(request.headers.get("authorization"))
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"jsonrpc": "2.0", "id": payload["id"], "result": {"echo": payload["params"]["arguments"]}},
        )

    set_fake_upstream(monkeypatch, upstream)
    response = client.post(
        "/mcp/proxy",
        headers=agent_headers(key),
        json=message("tools/call", {
            "name": "unrestricted.tool",
            "arguments": {"password": sensitive, "note": sensitive},
        }),
    )
    assert response.status_code == 200
    assert response.json()["result"]["echo"]["password"] == sensitive
    assert upstream_auth == [None]

    event = client.get("/mcp/events", headers=operator_headers(), params={"agent_id": agent_id})
    serialized_event = json.dumps(event.json())
    assert sensitive not in serialized_event
    assert "[REDACTED]" in serialized_event
    assert sensitive not in caplog.text
    db = session_factory()
    stored = db.query(MCPRequestEvent).filter_by(agent_id=agent_id).one()
    assert sensitive not in stored.payload_json
    db.close()


def test_streamable_http_sse_tool_list_is_filtered_and_preserved(gateway_client, monkeypatch):
    client, _ = gateway_client
    key, _, _ = add_agent(gateway_client[1])
    payload = message("tools/list")
    sse = (
        "data: " + json.dumps({
            "jsonrpc": "2.0",
            "id": payload["id"],
            "result": {"tools": [
                {"name": "filesystem.read", "description": "read"},
                {"name": "secret.tool", "description": "hidden"},
            ]},
        }) + "\n\n"
    ).encode()

    async def upstream(request):
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=sse,
        )

    set_fake_upstream(monkeypatch, upstream)
    response = client.post("/mcp/proxy", headers=agent_headers(key), json=payload)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    forwarded = json.loads(response.text.removeprefix("data: ").strip())
    assert [tool["name"] for tool in forwarded["result"]["tools"]] == ["filesystem.read"]


def test_tool_definition_change_is_flagged(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    descriptions = iter(["first", "changed"])

    async def upstream(request):
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"jsonrpc": "2.0", "id": payload["id"], "result": {"tools": [
                {"name": "filesystem.read", "description": next(descriptions), "inputSchema": {"type": "object"}},
            ]}},
        )

    set_fake_upstream(monkeypatch, upstream)
    for request_id in (11, 12):
        response = client.post(
            "/mcp/proxy",
            headers=agent_headers(key),
            json=message("tools/list", request_id=request_id),
        )
        assert response.status_code == 200
    events = client.get(
        "/mcp/events",
        headers=operator_headers(),
        params={"agent_id": agent_id, "decision": "flag"},
    )
    assert len(events.json()["events"]) == 1
    assert "TOOL-DEFINITION-CHANGED" in events.json()["events"][0]["matched_rule_ids"]


def test_upstream_client_interaction_is_flagged_in_sse(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    server_request = {
        "jsonrpc": "2.0",
        "id": "server-1",
        "method": "sampling/createMessage",
        "params": {"messages": []},
    }
    response_message = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"tools": [{"name": "filesystem.read", "description": "read"}]},
    }
    frames = "".join(
        "data: " + json.dumps(item) + "\n\n"
        for item in (server_request, response_message)
    ).encode()

    async def upstream(_request):
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=frames,
        )

    set_fake_upstream(monkeypatch, upstream)
    response = client.post(
        "/mcp/proxy",
        headers=agent_headers(key),
        json=message("tools/list"),
    )
    assert response.status_code == 200
    events = client.get(
        "/mcp/events",
        headers=operator_headers(),
        params={"agent_id": agent_id, "decision": "flag"},
    )
    assert len(events.json()["events"]) == 1
    event = events.json()["events"][0]
    assert event["direction"] == "server_to_agent"
    assert "SERVER-TO-CLIENT-REQUEST" in event["matched_rule_ids"]


def test_upstream_failure_is_translated_and_audited(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)

    async def upstream(_request):
        return httpx.Response(503, text="private upstream detail")

    set_fake_upstream(monkeypatch, upstream)
    response = client.post("/mcp/proxy", headers=agent_headers(key), json=message("tools/list"))
    assert response.status_code == 502
    assert "private upstream detail" not in response.text
    events = client.get(
        "/mcp/events",
        headers=operator_headers(),
        params={"agent_id": agent_id},
    )
    assert events.json()["events"][0]["response_status"] == "error"


def test_protocol_version_metadata_is_checked_and_forwarded(gateway_client, monkeypatch):
    client, _ = gateway_client
    key, _, _ = add_agent(gateway_client[1])
    upstream_versions = []

    async def upstream(request):
        upstream_versions.append(request.headers.get("mcp-protocol-version"))
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"jsonrpc": "2.0", "id": payload["id"], "result": {"tools": []}},
        )

    set_fake_upstream(monkeypatch, upstream)
    current_message = message("tools/list")
    current_message["_meta"] = {
        "io.modelcontextprotocol": {"protocolVersion": "2026-07-28"},
    }
    current = client.post(
        "/mcp/proxy",
        headers={**agent_headers(key), "MCP-Protocol-Version": "2026-07-28"},
        json=current_message,
    )
    assert current.status_code == 200
    assert upstream_versions == ["2026-07-28"]

    mismatch = client.post(
        "/mcp/proxy",
        headers={**agent_headers(key), "MCP-Protocol-Version": "2025-11-25"},
        json=current_message,
    )
    assert mismatch.status_code == 400
    assert "HeaderMismatch" in mismatch.json()["error"]["message"]
    assert upstream_versions == ["2026-07-28"]


def test_oversized_request_is_rejected_before_upstream(gateway_client, monkeypatch):
    client, _ = gateway_client
    key, _, _ = add_agent(gateway_client[1])
    calls = []
    monkeypatch.setattr(mcp_interception, "MAX_REQUEST_BYTES", 64)

    async def upstream(request):
        calls.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    set_fake_upstream(monkeypatch, upstream)
    response = client.post(
        "/mcp/proxy",
        headers={**agent_headers(key), "Content-Type": "application/json"},
        content=json.dumps(message("tools/list", {"padding": "x" * 200})),
    )
    assert response.status_code == 413
    assert calls == []


def test_evaluator_exception_fails_closed(gateway_client, monkeypatch):
    client, _ = gateway_client
    key, _, _ = add_agent(gateway_client[1])
    calls = []

    async def upstream(request):
        calls.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    async def broken_decision(_event, _agent):
        raise RuntimeError("sensitive evaluator exception")

    set_fake_upstream(monkeypatch, upstream)
    monkeypatch.setattr(mcp_interception, "decision_hook", broken_decision)
    response = client.post("/mcp/proxy", headers=agent_headers(key), json=message("tools/list"))
    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32000
    assert calls == []


def test_session_is_bound_to_the_initializing_agent(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    first_key, _, first_id = add_agent(session_factory)
    second_key, _, second_id = add_agent(session_factory, name="second-agent", name_normalized="second-agent")
    upstream_calls = []

    async def upstream(request):
        upstream_calls.append(json.loads(request.content)["method"])
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "MCP-Session-Id": "session-one"},
            json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-11-25"}},
        )

    set_fake_upstream(monkeypatch, upstream)
    initialize = message("initialize", {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    })
    response = client.post("/mcp/proxy", headers=agent_headers(first_key), json=initialize)
    assert response.status_code == 200
    assert response.headers["mcp-session-id"] == "session-one"

    other_agent = client.post(
        "/mcp/proxy",
        headers={**agent_headers(second_key), "MCP-Session-Id": "session-one"},
        json=message("tools/list"),
    )
    assert other_agent.status_code == 404
    assert upstream_calls == ["initialize"]
    assert first_id != second_id
