import json

import httpx
import gateway

import mcp_interception
from auth import create_access_token
from database import AuditLog, MCPRequestEvent, MCPAgent
from test_api_key_auth import add_agent, gateway_client, operator_token, set_fake_upstream


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _read_token() -> str:
    return create_access_token({
        "sub": "1",
        "username": "reader",
        "is_admin": False,
        "scopes": ["gateway:read"],
    })


def test_indicator_list_and_test_endpoint_require_read_scope(gateway_client):
    client, _ = gateway_client
    assert client.get("/api/policies/sqli/indicators").status_code == 401
    headers = _headers(_read_token())
    indicators = client.get("/api/policies/sqli/indicators", headers=headers)
    assert indicators.status_code == 200
    assert len(indicators.json()["indicators"]) == 15
    result = client.post(
        "/api/policies/sqli/test",
        headers=headers,
        json={"payload": "1 UNION SELECT secret FROM users", "sql_mode": "none"},
    )
    assert result.status_code == 200
    assert result.json()["action"] == "block"
    assert result.json()["findings"][0]["id"] == "SQLI-003"


def test_indicator_update_is_admin_only_and_audited(gateway_client):
    client, session_factory = gateway_client
    url = "/api/policies/sqli/indicators/SQLI-003"
    assert client.put(url, headers=_headers(_read_token()), json={"enabled": False}).status_code == 403
    updated = client.put(url, headers=_headers(operator_token()), json={"enabled": False, "severity": "medium"})
    assert updated.status_code == 200
    assert updated.json()["enabled"] is False
    assert updated.json()["severity"] == "medium"
    db = session_factory()
    try:
        audit = db.query(AuditLog).filter_by(action="sqli_indicator_update").one()
        assert "SQLI-003" in audit.details
    finally:
        db.close()


def test_agent_sql_mode_and_allowlist_are_validated_and_audited(gateway_client):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    url = f"/mcp/agents/{agent_id}"
    updated = client.patch(
        url,
        headers=_headers(operator_token()),
        json={"sql_mode_overrides": {"db/query": "readonly"}, "sqli_allowlist": ["SQLI-001"]},
    )
    assert updated.status_code == 200
    assert updated.json()["sql_mode_overrides"] == {"db/query": "readonly"}
    assert updated.json()["sqli_allowlist"] == ["SQLI-001"]
    invalid = client.patch(
        url,
        headers=_headers(operator_token()),
        json={"sqli_allowlist": ["NOT-A-RULE"]},
    )
    assert invalid.status_code == 422
    db = session_factory()
    try:
        agent = db.query(MCPAgent).filter_by(id=agent_id).one()
        assert json.loads(agent.agent_metadata)["sql_mode_overrides"]["db/query"] == "readonly"
        audit = db.query(AuditLog).filter_by(action="agent_sqli_policy_override").one()
        assert "SQLI-001" in audit.details
    finally:
        db.close()


def test_high_sqli_rule_blocks_before_model_or_upstream(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    upstream_calls = []

    async def upstream(request):
        upstream_calls.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    set_fake_upstream(monkeypatch, upstream)
    model_calls = []

    def low_model_score(_payload):
        model_calls.append(True)
        return {"score": 0.01, "label": 0, "top_signals": [], "decision": "ALLOW", "fallback": False}

    monkeypatch.setattr("ml.inference.score_payload", low_model_score)
    response = client.post(
        "/mcp/proxy",
        headers=_headers(key),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "filesystem.read", "arguments": {"filter": "1 UNION SELECT password FROM users"}},
        },
    )
    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32000
    assert upstream_calls == []
    assert model_calls == []
    alert = next(alert for alert in gateway.anomaly_alerts if alert["rule_id"] == "SQLI-003")
    assert alert["evidence"]["sqli_findings"][0]["field_path"] == "arguments.filter"
    assert alert["decision"] == "BLOCK"
    db = session_factory()
    try:
        event = db.query(MCPRequestEvent).filter_by(agent_id=agent_id, method="tools/call").one()
        assert json.loads(event.matched_rule_ids) == ["SQLI-003"]
        assert event.decision_source == "rule"
        assert event.rule_risk_score >= 0.9
        assert json.loads(event.sqli_findings_json)[0]["field_path"] == "arguments.filter"
    finally:
        db.close()