import asyncio
import json

import httpx
import pytest

from auth import create_access_token
from database import MCPEventOutbox, NetworkFirewallEvent, NetworkFirewallRuleHistory
from network_firewall.config import FirewallConfig
from network_firewall.dns_security import SecureDNSResolver, normalize_hostname
from network_firewall.engine import NetworkFirewall
from network_firewall.ip_analysis import analyze_ip
from network_firewall.rules import NetworkRule, destination_matches
from network_firewall.transport import PinnedHTTPXTransport
from network_firewall import service as firewall_service
from test_api_key_auth import add_agent, gateway_client, operator_token, set_fake_upstream


class AllowRateLimit:
    async def allow(self, agent_id, destination):
        return True


def firewall_config(**overrides):
    values = {
        "enabled": True,
        "default_action": "BLOCK",
        "allowed_protocols": ("https",),
        "allowed_ports": (443,),
        "allowed_domains": (),
        "denied_domains": (),
        "block_private": True,
        "block_loopback": True,
        "block_link_local": True,
        "dns_timeout_seconds": 0.5,
        "connection_timeout_seconds": 1,
        "max_response_bytes": 1024,
        "max_connections": 100,
        "connection_limit_window_seconds": 60,
        "cache_ttl_seconds": 0,
    }
    values.update(overrides)
    return FirewallConfig(**values)


def rule(rule_id, destination, action, *, agent_id=None, port=None, protocol=None):
    return NetworkRule(
        rule_id=rule_id,
        destination=destination,
        action=action,
        agent_id=agent_id,
        port=port,
        protocol=protocol,
    )


def make_firewall(resolver, rules=(), *, config=None, events=None, event_recorder=None):
    async def resolve(hostname):
        return resolver(hostname)

    if events is not None:
        event_recorder = events.append
    elif event_recorder is None:
        from network_firewall.policy_manager import record_firewall_event

        event_recorder = record_firewall_event
    return NetworkFirewall(
        config or firewall_config(),
        resolver=SecureDNSResolver(resolve, timeout_seconds=0.5, cache_ttl_seconds=0),
        rules_provider=lambda: list(rules),
        event_recorder=event_recorder,
        rate_limiter=AllowRateLimit(),
    )


def test_ip_analysis_classifies_ipv4_and_ipv6():
    assert analyze_ip("127.0.0.1").is_loopback
    assert analyze_ip("169.254.169.254").is_link_local
    assert analyze_ip("10.0.0.1").is_private
    assert analyze_ip("2001:4860:4860::8888").is_global
    assert analyze_ip("64:ff9b::a00:1").is_private_network


def test_hostname_normalization_and_domain_boundary_matching():
    assert normalize_hostname("Api.Example.COM.") == "api.example.com"
    assert destination_matches("example.com", "example.com", ())
    assert not destination_matches("example.com", "example.com.attacker.test", ())
    assert destination_matches("*.example.com", "api.example.com", ())


def test_default_deny_and_admin_allow_after_safe_dns():
    async def verify():
        firewall = make_firewall(lambda _host: {"8.8.8.8"})
        denied = await firewall.evaluate_request(
            agent_id=7, destination="api.example.com", port=443, protocol="https",
        )
        assert denied.decision == "BLOCK"

        events = []
        firewall = make_firewall(
            lambda _host: {"8.8.8.8"},
            [rule("NET-ALLOW", "api.example.com", "ALLOW", agent_id=7, port=443, protocol="https")],
            events=events,
        )
        allowed = await firewall.evaluate_request(
            agent_id=7, destination="api.example.com", port=443, protocol="https",
        )
        assert allowed.decision == "ALLOW"
        assert allowed.resolved_addresses == ("8.8.8.8",)
        assert events[0]["decision"] == "ALLOW"

    asyncio.run(verify())


def test_prohibited_answer_in_mixed_dns_set_cannot_be_overridden():
    async def verify():
        firewall = make_firewall(
            lambda _host: {"8.8.8.8", "10.0.0.4"},
            [rule("NET-ALLOW", "api.example.com", "ALLOW")],
        )
        decision = await firewall.evaluate_request(
            agent_id=2, destination="api.example.com", port=443, protocol="https",
        )
        assert decision.decision == "BLOCK"
        assert decision.rule_id == "NET-SSRF"

    asyncio.run(verify())


def test_non_routable_documentation_ranges_remain_blocked_when_private_is_allowed():
    async def verify():
        firewall = make_firewall(
            lambda _host: {"192.0.2.1"},
            [rule("NET-ALLOW", "api.example.com", "ALLOW")],
            config=firewall_config(block_private=False),
        )
        decision = await firewall.evaluate_request(
            agent_id=2, destination="api.example.com", port=443, protocol="https",
        )
        assert decision.decision == "BLOCK"

    asyncio.run(verify())


def test_global_deny_precedes_agent_allow_and_dns_errors_fail_closed():
    async def verify():
        firewall = make_firewall(
            lambda _host: {"8.8.8.8"},
            [
                rule("NET-AGENT-ALLOW", "api.example.com", "ALLOW", agent_id=42),
                rule("NET-GLOBAL-DENY", "api.example.com", "BLOCK"),
            ],
        )
        decision = await firewall.evaluate_request(
            agent_id=42, destination="api.example.com", port=443, protocol="https",
        )
        assert decision.decision == "BLOCK"
        assert decision.rule_id == "NET-GLOBAL-DENY"

        def failed_resolver(_host):
            raise OSError("DNS unavailable")

        failing = make_firewall(failed_resolver, [rule("NET-ALLOW", "api.example.com", "ALLOW")])
        failed = await failing.evaluate_request(
            agent_id=42, destination="api.example.com", port=443, protocol="https",
        )
        assert failed.decision == "BLOCK"

    asyncio.run(verify())


def test_firewall_enforces_protocol_port_and_metadata_address():
    async def verify():
        firewall = make_firewall(lambda _host: {"8.8.8.8"})
        bad_protocol = await firewall.evaluate_request(
            agent_id=1, destination="api.example.com", port=443, protocol="http",
        )
        bad_port = await firewall.evaluate_request(
            agent_id=1, destination="api.example.com", port=8443, protocol="https",
        )
        metadata = await firewall.evaluate_request(
            agent_id=1, destination="169.254.169.254", port=443, protocol="https",
        )
        assert [bad_protocol.decision, bad_port.decision, metadata.decision] == ["BLOCK"] * 3

    asyncio.run(verify())


def test_configuration_rejects_production_permissive_defaults(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "production")
    monkeypatch.setenv("SENTINEL_NETWORK_FIREWALL_ENABLED", "true")
    monkeypatch.setenv("SENTINEL_NETWORK_FIREWALL_DEFAULT_ACTION", "ALLOW")
    with pytest.raises(ValueError, match="default to BLOCK"):
        FirewallConfig.from_env()


def test_firewall_read_api_and_admin_scope_rule_management(gateway_client):
    client, session_factory = gateway_client
    response = client.get("/network-firewall/status")
    assert response.status_code == 401

    read_only = create_access_token({
        "sub": "2",
        "scopes": ["gateway:read"],
        "type": "access",
    })
    response = client.get(
        "/network-firewall/status",
        headers={"Authorization": f"Bearer {read_only}"},
    )
    assert response.status_code == 200
    assert client.get(
        "/network-firewall/rules",
        headers={"Authorization": f"Bearer {read_only}"},
    ).status_code == 200
    assert client.post(
        "/network-firewall/rules",
        headers={"Authorization": f"Bearer {read_only}"},
        json={"action": "ALLOW", "destination": "api.example.com", "port": 443},
    ).status_code == 403

    headers = {"Authorization": f"Bearer {operator_token()}"}
    created = client.post(
        "/network-firewall/rules",
        headers=headers,
        json={"action": "ALLOW", "destination": "api.example.com", "port": 443},
    )
    assert created.status_code == 201
    rule_id = created.json()["rule_id"]
    updated = client.put(
        f"/network-firewall/rules/{rule_id}",
        headers=headers,
        json={"enabled": False},
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    history = client.get(
        "/network-firewall/rule-history",
        headers=headers,
        params={"rule_id": rule_id},
    )
    assert history.status_code == 200
    assert [entry["action"] for entry in history.json()] == ["updated", "created"]
    assert client.delete(f"/network-firewall/rules/{rule_id}", headers=headers).status_code == 204
    db = session_factory()
    try:
        assert db.query(NetworkFirewallRuleHistory).filter_by(rule_id=rule_id).count() == 3
    finally:
        db.close()


def test_firewall_decision_persists_to_existing_event_outbox(gateway_client):
    _, session_factory = gateway_client
    firewall = make_firewall(
        lambda _host: {"8.8.8.8"},
        [rule("NET-PERSIST", "api.example.com", "ALLOW")],
    )
    decision = asyncio.run(firewall.evaluate_request(
        agent_id=81, destination="api.example.com", port=443, protocol="https",
    ))
    assert decision.decision == "ALLOW"
    db = session_factory()
    try:
        persisted = db.query(NetworkFirewallEvent).filter_by(event_id=decision.event_id).one()
        assert persisted.destination == "api.example.com"
        assert persisted.decision == "ALLOW"
        outbox = db.query(MCPEventOutbox).filter_by(event_id=decision.event_id).one()
        assert outbox.decision == "allow"
        stream_payload = json.loads(outbox.payload_json)
        assert stream_payload["type"] == "network_firewall_event"
        assert stream_payload["data"]["decision"] == "allow"
    finally:
        db.close()


def test_mcp_proxy_checks_firewall_before_using_upstream(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, agent_id = add_agent(session_factory)
    calls = []

    async def upstream(request):
        calls.append(request)
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"jsonrpc": "2.0", "id": payload["id"], "result": {}},
        )

    set_fake_upstream(monkeypatch, upstream)
    firewall = make_firewall(
        lambda _host: {"8.8.8.8"},
        [rule("NET-TEST-ALLOW", "mcp.test", "ALLOW", port=80, protocol="http")],
        config=firewall_config(allowed_protocols=("http",), allowed_ports=(80,)),
    )
    monkeypatch.setattr(firewall_service, "_firewall", firewall)
    response = client.post(
        "/mcp/proxy",
        headers={"Authorization": f"Bearer {key}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert response.status_code == 200
    assert len(calls) == 1
    db = session_factory()
    try:
        assert db.query(NetworkFirewallEvent).filter_by(
            agent_id=str(agent_id),
            destination="mcp.test",
            decision="ALLOW",
        ).count() == 1
    finally:
        db.close()


def test_mcp_proxy_blocks_private_upstream_before_connecting(gateway_client, monkeypatch):
    client, session_factory = gateway_client
    key, _, _ = add_agent(session_factory)
    calls = []

    async def upstream(request):
        calls.append(request)
        return httpx.Response(200, json={})

    set_fake_upstream(monkeypatch, upstream)
    firewall = make_firewall(
        lambda _host: {"10.0.0.8"},
        [rule("NET-TEST-ALLOW", "mcp.test", "ALLOW", port=80, protocol="http")],
        config=firewall_config(allowed_protocols=("http",), allowed_ports=(80,)),
    )
    monkeypatch.setattr(firewall_service, "_firewall", firewall)
    response = client.post(
        "/mcp/proxy",
        headers={"Authorization": f"Bearer {key}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert response.status_code == 403
    assert calls == []


def test_pinned_transport_connects_to_validated_ip_but_preserves_host():
    async def verify():
        observed = {}

        async def handler(reader, writer):
            request_line = await reader.readline()
            headers = []
            while line := await reader.readline():
                if line == b"\r\n":
                    break
                headers.append(line.lower())
            observed["request_line"] = request_line
            observed["host_header"] = next(
                (line for line in headers if line.startswith(b"host:")), b"",
            )
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            transport = PinnedHTTPXTransport(
                hostname="mcp.example.test",
                address="127.0.0.1",
                timeout_seconds=1,
                max_connections=1,
            )
            async with httpx.AsyncClient(transport=transport, timeout=1) as client:
                response = await client.get(f"http://mcp.example.test:{port}/health")
            assert response.text == "ok"
            assert observed["request_line"].startswith(b"GET /health ")
            assert observed["host_header"] == f"host: mcp.example.test:{port}\r\n".encode()

            wrong_host = PinnedHTTPXTransport(
                hostname="mcp.example.test",
                address="127.0.0.1",
                timeout_seconds=1,
                max_connections=1,
            )
            with pytest.raises(httpx.TransportError):
                async with httpx.AsyncClient(transport=wrong_host, timeout=1) as client:
                    await client.get(f"http://attacker.example.test:{port}/")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(verify())
