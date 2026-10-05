import json
import secrets
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.websockets import WebSocketDisconnect

import auth
import database
import gateway
import httpx
import mcp_interception
from auth import create_access_token, create_agent_api_key, hash_api_key
from database import AuditLog, Base, MCPAgent

REAL_ASYNC_CLIENT = httpx.AsyncClient


def set_fake_upstream(monkeypatch, handler):
    monkeypatch.setattr(mcp_interception, "UPSTREAM_URL", "http://mcp.test/mcp")

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return REAL_ASYNC_CLIENT(*args, **kwargs)

    monkeypatch.setattr(mcp_interception.httpx, "AsyncClient", client_factory)


@pytest.fixture
def gateway_client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    test_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr(database, "SessionLocal", test_session)
    monkeypatch.setattr(gateway, "AUTH_FAILURE_LIMIT", 100)
    monkeypatch.setattr(gateway, "AGENT_RATE_LIMIT_REQUESTS", 100)
    monkeypatch.setattr(gateway, "RATE_LIMIT_REQUESTS", 100)
    monkeypatch.setattr(mcp_interception, "UPSTREAM_URL", "http://mcp.test/mcp")
    gateway.rate_limit_buckets.clear()
    gateway.last_seen_write_at.clear()
    gateway.last_success_audit_at.clear()
    mcp_interception.sessions_by_agent.clear()
    mcp_interception._pending_tasks.clear()
    mcp_interception._tool_definition_hashes.clear()
    mcp_interception._tool_list_snapshots.clear()
    mcp_interception._agent_slots.clear()
    mcp_interception._session_slots.clear()
    gateway.authentication_events.clear()
    gateway.request_log.clear()
    gateway.blocked_requests.clear()
    gateway.anomaly_alerts.clear()
    gateway.system_events.clear()

    async def fake_upstream(request):
        message = json.loads(request.content)
        if message["method"] == "tools/list":
            result = {"tools": [
                {"name": "filesystem.read", "description": "read", "inputSchema": {"type": "object"}},
                {"name": "not-allowed", "description": "hidden", "inputSchema": {"type": "object"}},
            ]}
        elif message["method"] == "tools/call":
            result = {"content": [{"type": "text", "text": "ok"}]}
        elif message["method"] == "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "test", "version": "1"}}
        else:
            result = {}
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"jsonrpc": "2.0", "id": message.get("id"), "result": result},
        )

    real_async_client = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(fake_upstream)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(mcp_interception.httpx, "AsyncClient", fake_client)
    with TestClient(gateway.app, base_url="http://localhost") as client:
        yield client, test_session
    engine.dispose()


def add_agent(session_factory, key=None, **overrides):
    key = key or create_agent_api_key()[0]
    lookup_id = key.split("_")[2]
    prefix = "_".join(key.split("_")[:3])
    db = session_factory()
    fields = {
        "name": "test-agent",
        "name_normalized": "test-agent",
        "credential_hash": hash_api_key(key),
        "credential_prefix": prefix,
        "credential_id": lookup_id,
        "allowed_tools": json.dumps(["filesystem.read"]),
        "environment": "test",
        "team": "security",
        "risk_level": "low",
        "status": "active",
        "is_active": True,
    }
    fields.update(overrides)
    agent = MCPAgent(**fields)
    db.add(agent)
    db.commit()
    db.refresh(agent)
    agent_id = agent.id
    db.close()
    return key, lookup_id, agent_id


def operator_token():
    return create_access_token({
        "sub": "1",
        "username": "operator",
        "is_admin": True,
        "scopes": ["gateway:read", "gateway:write", "gateway:admin"],
    })


def set_safe_gateway_mocks(monkeypatch):
    monkeypatch.setattr(
        gateway.policy_engine,
        "evaluate",
        lambda method, params: SimpleNamespace(allowed=True, reason="allowed", details=[]),
    )
    monkeypatch.setattr(
        gateway.request_analyzer,
        "analyze",
        lambda agent, request: {"anomaly": False, "reason": "", "severity": "LOW"},
    )
    monkeypatch.setattr(gateway.behavioral_monitor, "add_request", lambda agent, request: (False, None))


def test_valid_key_sets_identity_and_ignores_spoofed_agent_id(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    set_safe_gateway_mocks(monkeypatch)

    identity, error, _, _ = gateway.verify_agent_api_key(key, "127.0.0.1")
    assert error is None
    assert identity == {
        "id": agent_id,
        "agent_id": agent_id,
        "name": "test-agent",
        "environment": "test",
        "team": "security",
        "status": "active",
        "allowed_tools": ["filesystem.read"],
        "risk_level": "low",
    }

    response = client.post(
        "/mcp/proxy",
        headers={"Authorization": f"Bearer {key}", "X-Agent-ID": "spoofed"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "agent_id": "spoofed",
            "params": {"name": "filesystem.read", "arguments": {"path": "README.md"}},
        },
    )
    assert response.status_code == 200
    assert gateway.request_log[-1]["agent_id"] == "test-agent"
    assert key not in response.text
    db = session_factory()
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id).first()
    assert agent.credential_hash == hash_api_key(key)
    assert key not in agent.credential_hash
    assert db.query(AuditLog).filter(AuditLog.action == "agent_auth_success").count() == 1
    db.close()


def test_malformed_headers_reject_before_opening_database(gateway_client, monkeypatch):
    client, _ = gateway_client

    def database_must_not_be_opened():
        raise AssertionError("Malformed credentials must not touch the key store")

    monkeypatch.setattr(database, "SessionLocal", database_must_not_be_opened)
    for headers, params in [
        ({}, {}),
        ({"Authorization": "Bearer "}, {}),
        ({"Authorization": "Basic abc"}, {}),
        ({"Authorization": f"Bearer {'x' * 600}"}, {}),
        ({"Authorization": "Bearer malformed", "X-API-Key": "also-malformed"}, {}),
        ({"Authorization": "Bearer malformed"}, {"api_key": "not-accepted"}),
        ([("Authorization", "Bearer first"), ("Authorization", "Bearer second")], {}),
    ]:
        response = client.post("/mcp/proxy", headers=headers, params=params, json={"method": "x"})
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Unauthorized"


def test_unknown_wrong_revoked_and_suspended_keys_have_expected_status(gateway_client):
    client, session_factory = gateway_client
    key, lookup_id, agent_id = add_agent(session_factory)
    wrong_key = f"cye_test_{lookup_id}_{secrets.token_urlsafe(32)}"
    unknown_key, _, _ = create_agent_api_key()

    wrong = client.post("/mcp/proxy", headers={"Authorization": f"Bearer {wrong_key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    unknown = client.post("/mcp/proxy", headers={"Authorization": f"Bearer {unknown_key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()

    operator_headers = {"Authorization": f"Bearer {operator_token()}"}
    assert client.post(f"/mcp/agents/{agent_id}/suspend", headers=operator_headers).status_code == 200
    assert client.post("/mcp/proxy", headers={"Authorization": f"Bearer {key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 403
    assert client.post(f"/mcp/agents/{agent_id}/resume", headers=operator_headers).status_code == 200
    assert client.post("/mcp/proxy", headers={"Authorization": f"Bearer {key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 200

    assert client.post(f"/mcp/agents/{agent_id}/revoke", headers=operator_headers).status_code == 200
    revoked = client.post("/mcp/proxy", headers={"Authorization": f"Bearer {key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert revoked.status_code == 401
    assert revoked.json() == unknown.json()


def test_rotation_grace_period_and_immediate_invalidation(gateway_client):
    client, session_factory = gateway_client
    old_key, _, agent_id = add_agent(session_factory)
    headers = {"Authorization": f"Bearer {operator_token()}"}

    rotated = client.post(
        f"/mcp/agents/{agent_id}/rotate-credential?grace_period_seconds=60",
        headers=headers,
    )
    assert rotated.status_code == 200
    new_key = rotated.json()["credential"]
    assert client.post("/mcp/proxy", headers={"Authorization": f"Bearer {old_key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 200
    assert client.post("/mcp/proxy", headers={"Authorization": f"Bearer {new_key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 200

    db = session_factory()
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id).first()
    agent.previous_credential_expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    db.close()
    assert client.post("/mcp/proxy", headers={"Authorization": f"Bearer {old_key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 401

    immediate = client.post(
        f"/mcp/agents/{agent_id}/rotate-credential",
        headers=headers,
    )
    assert immediate.status_code == 200
    assert client.post("/mcp/proxy", headers={"Authorization": f"Bearer {new_key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 401


def test_failed_attempt_lockout_is_audited_without_key_material(gateway_client, monkeypatch, caplog):
    client, session_factory = gateway_client
    monkeypatch.setattr(gateway, "AUTH_FAILURE_LIMIT", 2)
    unknown, lookup_id, _ = create_agent_api_key()
    gateway.rate_limit_buckets.clear()

    for expected in (401, 401, 429):
        response = client.post("/mcp/proxy", headers={"Authorization": f"Bearer {unknown}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert response.status_code == expected

    assert unknown not in caplog.text
    db = session_factory()
    events = db.query(AuditLog).filter(AuditLog.action.in_([
        "agent_auth_unknown",
        "agent_auth_rate_limited",
    ])).all()
    assert len(events) >= 2
    assert all(unknown not in event.details for event in events)
    assert any(lookup_id in event.details for event in events)
    db.close()


def test_successful_authentication_does_not_consume_failed_attempt_budget(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, _ = add_agent(session_factory)
    monkeypatch.setattr(gateway, "AUTH_FAILURE_LIMIT", 1)
    monkeypatch.setattr(gateway, "AGENT_RATE_LIMIT_REQUESTS", 10)
    gateway.rate_limit_buckets.clear()

    for request_id in (1, 2, 3):
        response = client.post(
            "/mcp/proxy",
            headers={"Authorization": f"Bearer {key}"},
            json={"jsonrpc": "2.0", "id": request_id, "method": "tools/list"},
        )
        assert response.status_code == 200

    unknown_key, _, _ = create_agent_api_key()
    failed = client.post(
        "/mcp/proxy",
        headers={"Authorization": f"Bearer {unknown_key}"},
        json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
    )
    assert failed.status_code == 401


def test_operator_token_is_not_agent_key_and_gateway_routes_default_to_operator_auth(gateway_client):
    client, _ = gateway_client
    operator = operator_token()

    agent_response = client.post(
        "/mcp/proxy",
        headers={"Authorization": f"Bearer {operator}"},
        json={"method": "tools/call"},
    )
    assert agent_response.status_code == 401
    assert client.get("/logs").status_code == 401
    assert client.get("/ml/health").status_code == 401
    assert client.get("/health").status_code == 200
    assert client.get("/logs", headers={"Authorization": f"Bearer {operator}"}).status_code == 200


def test_authentication_fails_closed_when_store_is_unavailable(gateway_client, monkeypatch):
    client, _ = gateway_client
    key, _, _ = create_agent_api_key()

    def unavailable_store():
        raise OSError("database unavailable")

    monkeypatch.setattr(database, "SessionLocal", unavailable_store)
    response = client.post("/mcp/proxy", headers={"Authorization": f"Bearer {key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 503
    assert key not in response.text


def test_last_seen_write_is_debounced(gateway_client):
    _, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    gateway.last_seen_write_at[agent_id] = time.monotonic()

    db = session_factory()
    original_seen = datetime(2025, 1, 1)
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id).first()
    agent.last_seen = original_seen
    db.commit()
    db.close()
    identity, error, _, _ = gateway.verify_agent_api_key(key, "127.0.0.1")
    assert identity is not None and error is None
    db = session_factory()
    assert db.query(MCPAgent).filter(MCPAgent.id == agent_id).first().last_seen == original_seen
    db.close()


def test_successful_traffic_is_rate_limited_per_agent(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    set_safe_gateway_mocks(monkeypatch)
    monkeypatch.setattr(gateway, "AGENT_RATE_LIMIT_REQUESTS", 1)
    gateway.rate_limit_buckets.clear()

    first = client.post("/mcp/proxy", headers={"Authorization": f"Bearer {key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    second = client.post("/mcp/proxy", headers={"Authorization": f"Bearer {key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert first.status_code == 200
    assert second.status_code == 429
    db = session_factory()
    event = db.query(AuditLog).filter(AuditLog.action == "agent_auth_rate_limited").first()
    assert event is not None
    assert str(agent_id) in event.details
    assert key not in event.details
    db.close()

def test_verifier_uses_constant_time_hash_comparison(monkeypatch):
    calls = []
    original = auth.hmac.compare_digest

    def compare_digest(left, right):
        calls.append((left, right))
        return original(left, right)

    monkeypatch.setattr(auth.hmac, "compare_digest", compare_digest)
    assert auth.verify_api_key("candidate", auth.hash_api_key("candidate"))
    assert len(calls) == 1


def test_live_websocket_requires_a_one_use_operator_ticket(gateway_client):
    client, _ = gateway_client
    token = operator_token()

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/mcp/ws/traffic", headers={"host": "localhost"}):
            pass

    ticket_response = client.post(
        "/auth/ws-ticket",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ticket_response.status_code == 200
    ticket = ticket_response.json()["ticket"]
    protocols = ["cybereye.v1", f"cybereye-ticket.{ticket}"]
    with client.websocket_connect(
        "/mcp/ws/traffic",
        subprotocols=protocols,
        headers={"host": "localhost"},
    ) as websocket:
        assert websocket.accepted_subprotocol == "cybereye.v1"
        assert websocket.receive_json()["type"] == "snapshot"

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/mcp/ws/traffic",
            subprotocols=protocols,
            headers={"host": "localhost"},
        ):
            pass


def test_legacy_plaintext_agent_key_is_hashed_and_scrubbed(monkeypatch):
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE mcp_agents ("
            "id INTEGER PRIMARY KEY, name VARCHAR(100), name_normalized VARCHAR(100), "
            "credential_hash VARCHAR(255), credential_prefix VARCHAR(16), "
            "api_key VARCHAR(255) UNIQUE)"
        )
        key, lookup_id, prefix = create_agent_api_key()
        connection.exec_driver_sql(
            "INSERT INTO mcp_agents "
            "(id, name, name_normalized, credential_hash, credential_prefix, api_key) "
            "VALUES (1, 'legacy-agent', 'legacy-agent', ?, ?, ?)",
            (key, "sk_sentinel_", key),
        )

    monkeypatch.setattr(database, "engine", engine)
    database.ensure_mcp_agent_schema()
    with engine.connect() as connection:
        stored_hash, retired_value, stored_id, stored_prefix = connection.exec_driver_sql(
            "SELECT credential_hash, api_key, credential_id, credential_prefix FROM mcp_agents WHERE id=1"
        ).one()
    assert stored_hash == hash_api_key(key)
    assert key not in retired_value
    assert stored_id == lookup_id
    assert stored_prefix == prefix
    engine.dispose()
