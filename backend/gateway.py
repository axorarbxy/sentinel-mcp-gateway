"""
Sentinel-MCP Gateway - AI/ML Security Monitoring Framework
Complete with Security Policies + ML Anomaly Detection + CyberEye Modules + Authentication + MCP Management + API Key Auth + WebSocket
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
for component in ("backend", "security", "monitoring", "machine_learning"):
    component_path = str(PROJECT_ROOT / component)
    if component_path not in sys.path:
        sys.path.insert(0, component_path)

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from typing import Set
import asyncio
import uvicorn
import json
import logging
import uuid
import secrets
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from time_utils import utcnow

# Import components
from policies import PolicyEngine, PolicyAction
from monitor import BehavioralMonitor, RequestAnalyzer
from modules.module_manager import ModuleManager
from gateway_plugins import GatewayPluginManager
from auth import decode_token, hash_api_key, parse_agent_api_key, verify_api_key
import mcp_interception
from shell_policy_hook import install as install_shell_policy_hook
from shared_state import (
    SharedStateUnavailable,
    close_shared_state,
    configure_shared_state,
    get_shared_state,
)
from event_pipeline import (
    EVENT_CONSUMER_GROUP,
    open_broker_message,
    protect_broker_message,
    run_event_consumer,
    run_outbox_publisher,
    update_outbox_payload,
    validate_event_security_configuration,
)
from event_transports import close_event_transports, validate_transport_configuration

# Import auth routes
from auth_routes import router as auth_router
from sqli_routes import router as sqli_router
from ml.inference import get_model_info, score_payload
from ml.network_flow_inference import get_network_flow_model_info, score_network_flow_csv

# Import MCP management routes
from mcp_routes import router as mcp_router

# Import ML Scanner
from ml_scanner import setup_ml_routes

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============ CREATE APP FIRST ============
install_shell_policy_hook()

async def _relay_shared_messages() -> None:
    """Fan Redis events/control messages out to this worker's local connections."""
    while True:
        state = get_shared_state()
        try:
            async for message in state.listen():
                if message.get("worker_id") == state.worker_id:
                    continue
                if message.get("kind") == "event":
                    event = message.get("event")
                    if isinstance(event, dict):
                        try:
                            event = open_broker_message(event)
                        except RuntimeError:
                            logger.exception("Rejected unauthenticated or undecryptable broker event")
                            continue
                        # Durable outbox messages carry the dashboard event under payload.
                        if isinstance(event.get("payload"), dict) and event.get("event_id"):
                            event = event["payload"]
                        await traffic_broadcaster.broadcast_local(event)
                elif message.get("kind") == "cancel":
                    request_key = message.get("request_key")
                    if isinstance(request_key, str):
                        mcp_interception.cancel_local_request(request_key)
                if state is not get_shared_state():
                    break
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Shared-state subscription failed; reconnecting")
            await asyncio.sleep(1)


async def _deliver_mcp_stream_event(message: dict) -> None:
    """Deliver a durable stream event to local sockets and the other workers."""
    if message.get("type") == "security_correlation" and isinstance(message.get("data"), dict):
        data = message["data"]
        alert = create_or_update_alert(
            agent_id=str(data.get("agent_id", "unknown")),
            alert_type="rule_based",
            reason=str(data.get("decision_reason", "Cross-event security correlation")),
            severity=str(data.get("severity", "HIGH")).upper(),
            request_data={
                "method": data.get("method"),
                "trigger_event_id": data.get("trigger_event_id"),
                "matched_rule_ids": data.get("matched_rule_ids", []),
                "correlation_window_seconds": data.get("correlation_window_seconds"),
            },
            event_id=str(data.get("event_id", "")),
            decision="FLAG",
        )
        correlation_rule = next(
            (value for value in data.get("matched_rule_ids", []) if isinstance(value, str)),
            "CEP-UNKNOWN",
        )
        alert["rule_id"] = correlation_rule
        alert["risk"]["rule_score"] = max(alert["risk"].get("rule_score", 0), 95)
        alert["risk"]["score"] = max(alert["risk"].get("score", 0), 95)
        alert["evidence"]["rule"] = correlation_rule
        alert["evidence"]["explanation"] = str(data.get("decision_reason", "Cross-event security correlation"))
        await traffic_broadcaster.broadcast(message)
    elif message.get("type") == "mcp_event" and isinstance(message.get("data"), dict):
        await traffic_broadcaster.broadcast(message)


@asynccontextmanager
async def gateway_lifespan(_app):
    validate_event_security_configuration()
    validate_transport_configuration()
    state = await configure_shared_state()
    await state.ensure_event_consumer_group(EVENT_CONSUMER_GROUP)
    restore_behavioral_models()
    restore_persisted_alerts()
    subscriber = asyncio.create_task(_relay_shared_messages(), name="shared-state-subscriber")
    publisher = asyncio.create_task(run_outbox_publisher(), name="mcp-event-outbox-publisher")
    consumer = asyncio.create_task(
        run_event_consumer(_deliver_mcp_stream_event),
        name="mcp-event-dashboard-consumer",
    )
    try:
        yield
    finally:
        for task in (subscriber, publisher, consumer):
            task.cancel()
        for task in (subscriber, publisher, consumer):
            try:
                await task
            except asyncio.CancelledError:
                pass
        await close_event_transports()
        await close_shared_state()


API_TAGS = [
    {"name": "authentication", "description": "User registration, login, and token lifecycle."},
    {"name": "mcp-management", "description": "Manage MCP agents, servers, and security policies."},
    {"name": "MCP Proxy", "description": "Authenticated MCP JSON-RPC traffic enforcement."},
    {"name": "Monitoring", "description": "Gateway health, request activity, and detection telemetry."},
    {"name": "Real-time", "description": "WebSocket traffic stream for live dashboard updates."},
    {"name": "CyberEye", "description": "CyberEye module analysis, alerts, and risk data."},
    {"name": "ML Security", "description": "QR and URL security-scanning capabilities."},
]

app = FastAPI(
    lifespan=gateway_lifespan,
    title="Sentinel-MCP Gateway API",
    summary="Runtime security and monitoring for AI agents using MCP.",
    description="""
## Sentinel-MCP API

Use this API to register MCP agents, enforce policy checks on tool calls, and
inspect security, system, and behavioral-monitoring telemetry.

The authenticated `POST /mcp/proxy` endpoint validates and forwards MCP
Streamable HTTP JSON-RPC traffic to the authenticated agent's configured
upstream, or `SENTINEL_MCP_UPSTREAM_URL` when that agent has no override. Tool calls are
checked against each agent's `allowed_tools`; redacted interception events are
available through the operator-protected `GET /mcp/events` endpoint.

### Authenticating MCP proxy requests

Create an MCP agent, then send its API key as
`Authorization: Bearer sk_sentinel_...` when calling **POST /mcp/proxy**.
Malformed MCP requests are reported as system events; policy and behavioral
signals are reported as security detections.
""",
    version="2.0.0",
    openapi_tags=API_TAGS,
    docs_url="/docs",
    redoc_url="/redoc",
    swagger_ui_parameters={"persistAuthorization": True, "displayRequestDuration": True},
    contact={"name": "Sentinel-MCP"},
)

# Deployment controls are opt-in locally and enforced by environment in a
# reverse-proxy or production deployment. Never hard-code certificates/keys.
if os.getenv("SENTINEL_FORCE_HTTPS", "false").lower() == "true":
    app.add_middleware(HTTPSRedirectMiddleware)

allowed_hosts = [
    host.strip()
    for host in os.getenv("SENTINEL_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if host.strip()
]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

RATE_LIMIT_REQUESTS = max(1, int(os.getenv("SENTINEL_RATE_LIMIT_REQUESTS", "60")))
RATE_LIMIT_WINDOW_SECONDS = max(1, int(os.getenv("SENTINEL_RATE_LIMIT_WINDOW_SECONDS", "60")))
WS_MAX_CONNECTIONS = max(1, int(os.getenv("SENTINEL_WS_MAX_CONNECTIONS", "200")))
WS_CONTROL_RATE = max(1, int(os.getenv("SENTINEL_WS_CONTROL_RATE", "60")))
WS_MAX_CONTROL_BYTES = max(256, min(16_384, int(os.getenv("SENTINEL_WS_MAX_CONTROL_BYTES", "4096"))))
WS_TICKET_RATE = max(1, int(os.getenv("SENTINEL_WS_TICKET_RATE", "20")))
AUTH_FAILURE_LIMIT = max(1, int(os.getenv("SENTINEL_AUTH_FAILURE_LIMIT", "10")))
AUTH_FAILURE_WINDOW_SECONDS = max(1, int(os.getenv("SENTINEL_AUTH_FAILURE_WINDOW_SECONDS", "60")))
AGENT_RATE_LIMIT_REQUESTS = max(1, int(os.getenv("SENTINEL_AGENT_RATE_LIMIT_REQUESTS", str(RATE_LIMIT_REQUESTS))))
last_seen_write_at: dict[int, float] = {}
last_success_audit_at: dict[int, float] = {}
DUMMY_API_KEY_HASH = hash_api_key("cye_dummy_auth_key_for_timing_equalization")
gateway_metrics = {
    "started_at": time.time(),
    "requests": 0,
    "errors": 0,
    "latencies_ms": deque(maxlen=1000),
    "status_codes": defaultdict(int),
    "rate_limited": 0,
}


async def _allow_limited_request(
    keys: list[tuple[str, str]],
    limit: int,
    window_seconds: int,
) -> bool:
    return await get_shared_state().consume_rate_limit(keys, limit, window_seconds)




async def _finish_auth_attempt(keys: list[tuple[str, str]], token: str, *, failed: bool) -> None:
    try:
        await get_shared_state().finish_auth_attempt(keys, token, failed=failed)
    except SharedStateUnavailable:
        logger.exception("Failed to finalize shared authentication attempt")


@app.middleware("http")
async def gateway_security_and_metrics(request: Request, call_next):
    """Enforce operator authentication by default and add request telemetry."""
    request_id = request.headers.get("X-Request-ID", f"req_{uuid.uuid4().hex}")
    started = time.perf_counter()

    public_paths = {
        "/health", "/docs", "/redoc", "/openapi.json",
        "/auth/register", "/auth/login", "/auth/refresh",
    }
    if (
        request.method != "OPTIONS"
        and request.url.path not in public_paths
        and request.url.path != "/mcp/proxy"
    ):
        authorization = request.headers.getlist("authorization")
        token = authorization[0][7:].strip() if len(authorization) == 1 and authorization[0].startswith("Bearer ") else ""
        payload = decode_token(token) if token else None
        if not payload or payload.get("type") != "access":
            response = JSONResponse(
                status_code=401,
                content={"detail": "Operator access token required"},
            )
            response.headers["X-Request-ID"] = request_id
            return response
        if "gateway:read" not in set(payload.get("scopes", [])):
            response = JSONResponse(
                status_code=403,
                content={"detail": "Insufficient OAuth scope"},
            )
            response.headers["X-Request-ID"] = request_id
            return response
        request.state.operator_identity = payload

    try:
        response = await call_next(request)
    except Exception:
        gateway_metrics["errors"] += 1
        raise
    finally:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        gateway_metrics["requests"] += 1
        gateway_metrics["latencies_ms"].append(latency_ms)

    gateway_metrics["status_codes"][str(response.status_code)] += 1
    if response.status_code >= 500:
        gateway_metrics["errors"] += 1
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Response-Time-Ms"] = str(latency_ms)
    return response


def custom_openapi():
    """Expose the MCP-agent API key in Swagger's Authorize dialog."""
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        summary=app.summary,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["MCPAgentKey"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "cye_ agent API key",
        "description": "Use the API key generated when registering an MCP agent.",
    }
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi

# Enable CORS only for configured dashboard origins; bearer auth does not use cookies.
cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "SENTINEL_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "MCP-Session-Id", "X-Request-ID"],
)

# ============ INCLUDE AUTH ROUTES ============
app.include_router(auth_router)
app.include_router(sqli_router)

# ============ INCLUDE MCP MANAGEMENT ROUTES ============
app.include_router(mcp_router)

# ============ SETUP ML ROUTES ============
setup_ml_routes(app)

# ============ INITIALIZE COMPONENTS ============
policy_engine = PolicyEngine()
behavioral_monitor = BehavioralMonitor(window_size=100, contamination=0.1)
request_analyzer = RequestAnalyzer()
gateway_plugins = GatewayPluginManager()

# Initialize CyberEye modules
cybereye = ModuleManager()

# Track requests
request_log = []
blocked_requests = []
anomaly_alerts = []
system_events = []
authentication_events = deque(maxlen=1000)


def create_or_update_alert(
    *, agent_id: str, alert_type: str, reason: str, severity: str,
    request_data: dict, event_id: str, decision: str = "BLOCK", score=None,
    occurred_at: datetime | None = None,
):
    """Correlate equivalent detections while retaining each raw request log.

    An alert represents analyst work; request_log remains the immutable event
    stream. Matching agent, detection, tool and reason within five minutes are
    intentionally shown as one alert with an occurrence count.
    """
    now = occurred_at or utcnow()
    method = request_data.get("method", "unknown")
    fingerprint = f"{agent_id}|{alert_type}|{method}|{reason}"
    for alert in reversed(anomaly_alerts):
        if alert["fingerprint"] != fingerprint:
            continue
        previous = datetime.fromisoformat(alert["last_seen"])
        if (now - previous).total_seconds() <= 300:
            alert["occurrence_count"] += 1
            alert["last_seen"] = now.isoformat()
            alert["event_ids"].append(event_id)
            alert["evidence"]["latest_request"] = request_data
            if score is not None:
                alert["risk"]["anomaly_score"] = score
            return alert

    rule_id = "MCP-007" if "operation chain" in reason.lower() else "MCP-BEH-001"
    risk_score = 85 if severity == "HIGH" else 65 if severity == "MEDIUM" else 35
    alert = {
        "id": f"alt_{uuid.uuid4().hex}",
        "fingerprint": fingerprint,
        "event_ids": [event_id],
        "timestamp": now.isoformat(),
        "first_seen": now.isoformat(),
        "last_seen": now.isoformat(),
        "occurrence_count": 1,
        "agent_id": agent_id,
        "type": alert_type,
        "title": "Suspicious MCP operation chain" if "operation chain" in reason.lower() else reason,
        "category": "MCP_TOOL_ABUSE" if alert_type == "rule_based" else "BEHAVIORAL_ANOMALY",
        "reason": reason,
        "severity": severity,
        "status": "NEW",
        "decision": decision,
        "rule_id": rule_id,
        "risk": {"score": risk_score, "rule_score": 32 if alert_type == "rule_based" else 0, "anomaly_score": score},
        "evidence": {
            "rule": rule_id,
            "method": method,
            "latest_request": request_data,
            "explanation": f"{method} matched {rule_id}: {reason}",
        },
        "request": request_data,
    }
    anomaly_alerts.append(alert)
    return alert


def restore_persisted_alerts() -> None:
    """Rebuild the in-memory detection view from durable MCP request events."""
    from database import MCPRequestEvent, SessionLocal

    db = SessionLocal()
    existing_alerts = list(anomaly_alerts)
    try:
        events = (
            db.query(MCPRequestEvent)
            .filter(
                MCPRequestEvent.decision.in_(("block", "flag")),
                MCPRequestEvent.sqli_findings_json != "[]",
            )
            .order_by(MCPRequestEvent.timestamp.asc(), MCPRequestEvent.id.asc())
            .all()
        )
        anomaly_alerts.clear()
        for event in events:
            try:
                findings = json.loads(event.sqli_findings_json or "[]")
            except (TypeError, ValueError):
                logger.warning("Skipping persisted detection with invalid findings event_id=%s", event.event_id)
                continue
            if not isinstance(findings, list) or not findings:
                continue

            indicator_ids = list(dict.fromkeys(
                item.get("id", "SQLI-UNKNOWN")
                for item in findings
                if isinstance(item, dict)
            ))
            if not indicator_ids:
                continue
            reason = "SQL injection indicators: " + ", ".join(indicator_ids[:4])
            severity_order = {"low": 1, "medium": 2, "high": 3}
            severity = max(
                (str(item.get("severity", "low")).lower() for item in findings if isinstance(item, dict)),
                key=lambda value: severity_order.get(value, 0),
                default="low",
            ).upper()
            request_data = {
                "method": event.method,
                "tool_name": event.tool_name,
                "sqli_findings": findings,
                "decision_source": event.decision_source,
            }
            alert = create_or_update_alert(
                agent_id=event.agent_name,
                alert_type="rule_based",
                reason=reason,
                severity=severity,
                request_data=request_data,
                event_id=event.event_id,
                decision=event.decision.upper(),
                occurred_at=event.timestamp,
            )
            alert["rule_id"] = indicator_ids[0]
            alert["risk"]["rule_score"] = max(
                alert["risk"]["rule_score"],
                round(float(event.rule_risk_score or 0.0) * 100),
            )
            alert["risk"]["score"] = max(alert["risk"]["score"], alert["risk"]["rule_score"])
            alert["evidence"]["rule"] = alert["rule_id"]
            alert["evidence"]["sqli_findings"] = findings
            alert["evidence"]["explanation"] = reason
        logger.info("Restored %s security detection alerts from persisted MCP events", len(anomaly_alerts))
    except Exception:
        anomaly_alerts.clear()
        anomaly_alerts.extend(existing_alerts)
        logger.exception("Failed to restore persisted security detection alerts")
    finally:
        db.close()


def _argument_shape(arguments: Any) -> dict[str, int]:
    """Return bounded, content-free size/shape signals for adaptive monitoring."""
    try:
        serialized_size = len(json.dumps(arguments, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError, RecursionError):
        serialized_size = 0
    max_depth = 0
    key_count = 0
    string_bytes = 0
    pending = [(arguments, 1)]
    while pending:
        value, depth = pending.pop()
        max_depth = max(max_depth, depth)
        if isinstance(value, dict):
            key_count += len(value)
            for key, child in value.items():
                if isinstance(key, str):
                    string_bytes += len(key.encode("utf-8", errors="replace"))
                pending.append((child, depth + 1))
        elif isinstance(value, (list, tuple)):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            string_bytes += len(value.encode("utf-8", errors="replace"))
    return {
        "argument_bytes": min(serialized_size, 10_000_000),
        "argument_depth": min(max_depth, 10_000),
        "argument_keys": min(key_count, 1_000_000),
        "argument_string_bytes": min(string_bytes, 10_000_000),
    }


def restore_behavioral_models() -> None:
    """Rebuild per-agent Isolation Forests from the retained request history."""
    from database import MCPRequestEvent, SessionLocal

    behavioral_monitor.history.clear()
    behavioral_monitor.feature_history.clear()
    behavioral_monitor.allowed_tool_counts.clear()
    behavioral_monitor.total_allowed_samples.clear()
    behavioral_monitor.model_sample_counts.clear()
    behavioral_monitor.models.clear()
    behavioral_monitor.scalers.clear()
    behavioral_monitor.alerts.clear()
    behavioral_monitor.total_requests = 0
    behavioral_monitor.anomalies_detected = 0
    db = SessionLocal()
    try:
        agent_ids = [
            agent_id
            for (agent_id,) in db.query(MCPRequestEvent.agent_id).distinct().all()
        ]
        for agent_id in agent_ids:
            persisted_events = (
                db.query(MCPRequestEvent)
                .filter(MCPRequestEvent.agent_id == agent_id)
                .order_by(MCPRequestEvent.timestamp.desc(), MCPRequestEvent.id.desc())
                .limit(behavioral_monitor.window_size)
                .all()
            )
            for event in reversed(persisted_events):
                try:
                    payload = json.loads(event.payload_json or "{}")
                except (TypeError, ValueError):
                    payload = {}
                arguments = payload.get("arguments", {}) if isinstance(payload, dict) else {}
                arguments = arguments if isinstance(arguments, dict) else {}
                params = {
                    key: arguments[key]
                    for key in ("path", "command", "sql")
                    if key in arguments
                }
                behavioral_monitor.add_request(
                    str(agent_id),
                    {
                        "timestamp": event.timestamp.isoformat(),
                        "method": event.method,
                        "params": params,
                        "tool_name": event.tool_name,
                        "decision": event.decision,
                        **_argument_shape(arguments),
                    },
                )
        logger.info("Restored %s behavioral models from persisted MCP events", len(behavioral_monitor.models))
    except Exception:
        logger.exception("Failed to restore behavioral models from persisted MCP events")
        raise
    finally:
        db.close()


def performance_snapshot():
    """Return bounded in-process telemetry without exposing request contents."""
    latencies = list(gateway_metrics["latencies_ms"])
    average_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0
    return {
        "uptime_seconds": round(time.time() - gateway_metrics["started_at"], 2),
        "requests": gateway_metrics["requests"],
        "errors": gateway_metrics["errors"],
        "error_rate": round(gateway_metrics["errors"] / gateway_metrics["requests"] * 100, 2)
        if gateway_metrics["requests"] else 0,
        "average_latency_ms": average_latency,
        "throughput_per_second": round(gateway_metrics["requests"] / max(time.time() - gateway_metrics["started_at"], 1), 3),
        "status_codes": dict(gateway_metrics["status_codes"]),
        "rate_limited": gateway_metrics["rate_limited"],
    }


# ============ WEBSOCKET MANAGER ============
class TrafficBroadcaster:
    """Fan sanitized updates to this worker and other workers' sockets."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.subscriptions: dict[WebSocket, dict[str, Any]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> bool:
        async with self.lock:
            if len(self.active_connections) >= WS_MAX_CONNECTIONS:
                return False
            await websocket.accept(subprotocol="cybereye.v1")
            self.active_connections.add(websocket)
            self.subscriptions[websocket] = {"event_types": {"mcp_event", "security_correlation"}}
        logger.info("WebSocket connected (worker-local total: %s)", len(self.active_connections))
        return True

    @staticmethod
    def validate_subscription(filters: Any) -> dict[str, Any]:
        if not isinstance(filters, dict) or set(filters) - {"agent_ids", "event_types", "decisions"}:
            raise ValueError("Subscription supports only agent_ids, event_types, and decisions")
        normalized: dict[str, Any] = {}
        for key, maximum in (("agent_ids", 50), ("event_types", 16), ("decisions", 3)):
            values = filters.get(key)
            if values is None:
                continue
            if not isinstance(values, list) or len(values) > maximum:
                raise ValueError(f"{key} must be a list with at most {maximum} values")
            if key == "agent_ids":
                if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in values):
                    raise ValueError("agent_ids must contain positive integers")
                normalized[key] = set(values)
            else:
                if any(not isinstance(value, str) or not value or len(value) > 80 for value in values):
                    raise ValueError(f"{key} must contain non-empty strings of at most 80 characters")
                if key == "decisions" and any(value not in {"allow", "block", "flag"} for value in values):
                    raise ValueError("decisions may contain only allow, block, and flag")
                normalized[key] = set(values)
        return normalized

    async def subscribe(self, websocket: WebSocket, filters: Any) -> dict[str, Any]:
        normalized = self.validate_subscription(filters)
        async with self.lock:
            if websocket not in self.active_connections:
                raise ValueError("WebSocket is no longer connected")
            self.subscriptions[websocket] = normalized
        return {key: sorted(value) for key, value in normalized.items()}

    async def disconnect(self, websocket: WebSocket):
        async with self.lock:
            self.active_connections.discard(websocket)
            self.subscriptions.pop(websocket, None)
        logger.info("WebSocket disconnected (worker-local total: %s)", len(self.active_connections))

    async def broadcast_local(self, message: dict):
        async with self.lock:
            connections = list(self.active_connections)
        data = message.get("data") if isinstance(message.get("data"), dict) else {}

        async def deliver(connection: WebSocket) -> bool:
            async with self.lock:
                filters = self.subscriptions.get(connection, {})
            agent_ids = filters.get("agent_ids")
            if agent_ids is not None:
                try:
                    if int(data.get("agent_id")) not in agent_ids:
                        return False
                except (TypeError, ValueError):
                    return False
            event_types = filters.get("event_types")
            if event_types is not None and message.get("type") not in event_types:
                return False
            decisions = filters.get("decisions")
            if decisions is not None and data.get("decision") not in decisions:
                return False
            try:
                await asyncio.wait_for(connection.send_json(message), timeout=0.5)
            except Exception:
                logger.exception("WebSocket send failed")
                return True
            return False

        dead_connections = {connection for connection, failed in zip(
            connections, await asyncio.gather(*(deliver(connection) for connection in connections)),
        ) if failed}
        if dead_connections:
            async with self.lock:
                self.active_connections.difference_update(dead_connections)
                for connection in dead_connections:
                    self.subscriptions.pop(connection, None)

    async def broadcast(self, message: dict):
        """Send locally immediately, then publish to the other workers."""
        await self.broadcast_local(message)
        state = get_shared_state()
        if not state.is_distributed:
            return
        try:
            await state.publish_message({
                "kind": "event",
                "worker_id": state.worker_id,
                "event": protect_broker_message(message),
            })
        except RuntimeError:
            logger.exception("Cross-worker event protection is misconfigured")
        except SharedStateUnavailable:
            logger.exception("Cross-worker live-event publish failed")


# Global broadcaster instance
traffic_broadcaster = TrafficBroadcaster()


@app.post("/auth/ws-ticket", tags=["authentication"])
async def create_websocket_ticket(request: Request):
    """Issue a short-lived, one-use ticket for browsers that cannot set WS headers."""
    operator = getattr(request.state, "operator_identity", None)
    if not operator:
        raise HTTPException(status_code=401, detail="Operator access token required")
    source_ip = request.client.host if request.client else "unknown"
    try:
        allowed = await get_shared_state().consume_rate_limit(
            [("ws-ticket-user", str(operator["sub"])), ("ws-ticket-ip", source_ip)],
            WS_TICKET_RATE,
            60,
        )
    except SharedStateUnavailable:
        logger.exception("Shared state unavailable while rate-limiting WebSocket tickets")
        raise HTTPException(status_code=503, detail="WebSocket authentication unavailable")
    if not allowed:
        raise HTTPException(status_code=429, detail="WebSocket ticket rate limit exceeded")
    ticket = secrets.token_urlsafe(32)
    try:
        await get_shared_state().put_ws_ticket(ticket, int(operator["sub"]), ttl_seconds=30)
    except SharedStateUnavailable:
        logger.exception("Shared state unavailable while issuing WebSocket ticket")
        raise HTTPException(status_code=503, detail="WebSocket authentication unavailable")
    return {"ticket": ticket, "expires_in": 30}


# ============ AUTH HELPERS ============
def _append_auth_event(
    *,
    category: str,
    source_ip: str,
    key_prefix: str | None = None,
    agent_id: int | None = None,
) -> dict:
    event = {
        "type": "agent_authentication",
        "timestamp": utcnow().isoformat(),
        "category": category,
        "source_ip": source_ip,
        "key_prefix": key_prefix,
        "agent_id": agent_id,
    }
    authentication_events.append(event)
    if len(system_events) >= 1000:
        del system_events[0]
    system_events.append(event)
    return event


def _persist_auth_event(
    db,
    *,
    category: str,
    source_ip: str,
    key_prefix: str | None = None,
    agent_id: int | None = None,
) -> None:
    from database import AuditLog

    db.add(AuditLog(
        user_id=None,
        action=f"agent_auth_{category}",
        details=json.dumps({
            "target_agent_id": agent_id,
            "source_ip": source_ip,
            "key_prefix": key_prefix,
            "reason": category,
        }),
        timestamp=utcnow(),
    ))


async def verify_agent_api_key(api_key: str, source_ip: str):
    """Resolve a presented agent key through an indexed ID and enforce lifecycle state."""
    from database import MCPAgent, SessionLocal
    from sqlalchemy import or_

    parsed = parse_agent_api_key(api_key)
    is_legacy = api_key.startswith("sk_sentinel_") and len(api_key) <= 256
    lookup_id = parsed[0] if parsed else None
    key_prefix = f"cye_{api_key.split('_', 2)[1]}_{lookup_id}" if lookup_id else (
        "sk_sentinel_" if is_legacy else None
    )
    limiter_keys = [("ip", source_ip)]
    if lookup_id:
        limiter_keys.append(("key", key_prefix))
    try:
        attempt_token = await get_shared_state().begin_auth_attempt(
            limiter_keys, AUTH_FAILURE_LIMIT, AUTH_FAILURE_WINDOW_SECONDS,
        )
    except SharedStateUnavailable:
        logger.exception("Shared authentication state unavailable")
        return None, "store_unavailable", None, key_prefix

    if attempt_token is None:
        from database import SessionLocal

        audit_db = None
        try:
            audit_db = SessionLocal()
            _persist_auth_event(
                audit_db,
                category="rate_limited",
                source_ip=source_ip,
                key_prefix=key_prefix,
            )
            audit_db.commit()
        except Exception:
            if audit_db is not None:
                audit_db.rollback()
            logger.exception("Failed to persist agent authentication lockout event")
        finally:
            if audit_db is not None:
                audit_db.close()
        _append_auth_event(
            category="rate_limited",
            source_ip=source_ip,
            key_prefix=key_prefix,
        )
        return None, "rate_limited", None, key_prefix

    if parsed is None and not is_legacy:
        _append_auth_event(
            category="malformed",
            source_ip=source_ip,
            key_prefix=key_prefix,
        )
        return None, "malformed", None, key_prefix

    db = None
    try:
        db = SessionLocal()
        agent = None
        matched = False
        if lookup_id:
            agent = db.query(MCPAgent).filter(
                or_(
                    MCPAgent.credential_id == lookup_id,
                    MCPAgent.previous_credential_id == lookup_id,
                )
            ).first()
            expected_hash = DUMMY_API_KEY_HASH
            previous_key = False
            if agent:
                if agent.credential_id == lookup_id:
                    expected_hash = agent.credential_hash or DUMMY_API_KEY_HASH
                elif agent.previous_credential_id == lookup_id:
                    expected_hash = agent.previous_credential_hash or DUMMY_API_KEY_HASH
                    previous_key = True
            matched = verify_api_key(api_key, expected_hash)
        else:
            # Compatibility for pre-lookup-ID credentials; new keys never use this path.
            legacy_agents = db.query(MCPAgent).filter(
                MCPAgent.credential_prefix == "sk_sentinel_"
            ).all()
            matched = False
            for candidate in legacy_agents:
                current_match = verify_api_key(api_key, candidate.credential_hash or DUMMY_API_KEY_HASH)
                previous_match = verify_api_key(api_key, candidate.previous_credential_hash or DUMMY_API_KEY_HASH)
                if current_match or previous_match:
                    agent = candidate
                    matched = True
                    break
            previous_key = bool(agent and agent.previous_credential_hash and
                                verify_api_key(api_key, agent.previous_credential_hash))

        category = "unknown"
        if agent is not None and matched:
            if previous_key and (
                agent.previous_credential_expires_at is None
                or agent.previous_credential_expires_at <= utcnow()
            ):
                category = "revoked"
            elif agent.status == "suspended":
                category = "suspended"
            elif agent.status == "revoked" or agent.deleted_at is not None or not agent.is_active:
                category = "revoked"
            elif agent.status not in (None, "active"):
                category = "revoked"
            else:
                allowed_tools = []
                try:
                    parsed_tools = json.loads(agent.allowed_tools or "[]")
                    allowed_tools = parsed_tools if isinstance(parsed_tools, list) else []
                except (TypeError, ValueError):
                    allowed_tools = []
                try:
                    agent_metadata = json.loads(agent.agent_metadata or "{}")
                except (TypeError, ValueError):
                    agent_metadata = {}
                if not isinstance(agent_metadata, dict):
                    agent_metadata = {}
                identity = {
                    "id": agent.id,
                    "agent_id": agent.id,
                    "name": agent.name,
                    "environment": agent.environment or "dev",
                    "team": agent.team,
                    "status": agent.status or "active",
                    "allowed_tools": allowed_tools,
                    "risk_level": agent.risk_level or "low",
                    "upstream_url": agent_metadata.get("upstream_url"),
                    "upstream_name": agent_metadata.get("upstream_name"),
                    "upstream_token_env": agent_metadata.get("upstream_token_env"),
                }
                now = time.monotonic()
                should_update_seen = now - last_seen_write_at.get(agent.id, 0.0) >= 60
                should_audit_success = now - last_success_audit_at.get(agent.id, 0.0) >= 60
                if should_update_seen:
                    agent.last_seen = utcnow()
                    last_seen_write_at[agent.id] = now
                if should_audit_success:
                    _persist_auth_event(
                        db,
                        category="success",
                        source_ip=source_ip,
                        key_prefix=key_prefix,
                        agent_id=agent.id,
                    )
                    last_success_audit_at[agent.id] = now
                if should_update_seen or should_audit_success:
                    db.commit()
                if should_audit_success:
                    _append_auth_event(
                        category="success",
                        source_ip=source_ip,
                        key_prefix=key_prefix,
                        agent_id=agent.id,
                    )
                db.close()
                await _finish_auth_attempt(limiter_keys, attempt_token, failed=False)
                return identity, None, None, key_prefix

        _persist_auth_event(
            db,
            category=category,
            source_ip=source_ip,
            key_prefix=key_prefix,
            agent_id=agent.id if agent is not None and matched else None,
        )
        db.commit()
        _append_auth_event(
            category=category,
            source_ip=source_ip,
            key_prefix=key_prefix,
            agent_id=agent.id if agent is not None and matched else None,
        )
        db.close()
        return None, category, None, key_prefix
    except Exception:
        logger.exception("Agent credential store unavailable during verification")
        if db is not None:
            db.rollback()
            db.close()
        await _finish_auth_attempt(limiter_keys, attempt_token, failed=False)
        return None, "store_unavailable", None, key_prefix


# ============ MCP PROXY ENDPOINT (AUTHENTICATED) ============
@app.post(
    "/mcp/proxy",
    tags=["MCP Proxy"],
    summary="Intercept and forward authenticated MCP Streamable HTTP messages",
    openapi_extra={"security": [{"MCPAgentKey": []}]},
)
async def mcp_proxy(request: Request):
    """Authenticate the agent, then validate, decide, record, and proxy JSON-RPC."""
    auth_headers = request.headers.getlist("authorization")
    auth_header = auth_headers[0] if len(auth_headers) == 1 else ""
    source_ip = request.client.host if request.client else "unknown"
    has_key_query = any(
        name.lower() in {"api_key", "apikey", "authorization", "credential", "key", "token"}
        for name, _ in request.query_params.multi_items()
    )
    malformed = (
        has_key_query
        or len(auth_headers) != 1
        or len(auth_header.encode("utf-8")) > 512
        or not auth_header.startswith("Bearer ")
        or not auth_header[7:].strip()
        or len(auth_header[7:].strip()) > 256
        or "," in auth_header[7:]
        or request.headers.get("x-api-key") is not None
    )
    if malformed:
        try:
            allowed = await _allow_limited_request(
                [("ip", source_ip)], AUTH_FAILURE_LIMIT, AUTH_FAILURE_WINDOW_SECONDS,
            )
        except SharedStateUnavailable:
            logger.exception("Shared state unavailable during malformed credential rate limiting")
            return JSONResponse(status_code=503, content={"jsonrpc": "2.0", "error": {
                "code": -32001, "message": "Authentication service unavailable",
            }})
        category = "malformed" if allowed else "rate_limited"
        event = _append_auth_event(category=category, source_ip=source_ip)
        logger.warning("Agent authentication failed category=%s source_ip=%s", category, source_ip)
        await traffic_broadcaster.broadcast({"type": "authentication_event", "data": dict(event)})
        status_code = 401 if allowed else 429
        return JSONResponse(
            status_code=status_code,
            content={"jsonrpc": "2.0", "error": {
                "code": -32001,
                "message": "Unauthorized" if allowed else "Authentication rate limit exceeded",
            }},
            headers={"Retry-After": str(AUTH_FAILURE_WINDOW_SECONDS)} if not allowed else None,
        )

    api_key = auth_header[7:].strip()
    agent_info, error, _, key_prefix = await verify_agent_api_key(api_key, source_ip)
    if error:
        logger.warning(
            "Agent authentication failed category=%s source_ip=%s key_prefix=%s",
            error, source_ip, key_prefix,
        )
        status_code, message = {
            "store_unavailable": (503, "Authentication service unavailable"),
            "suspended": (403, "Agent is not permitted"),
            "rate_limited": (429, "Authentication rate limit exceeded"),
        }.get(error, (401, "Unauthorized"))
        if authentication_events:
            await traffic_broadcaster.broadcast({
                "type": "authentication_event",
                "data": dict(authentication_events[-1]),
            })
        return JSONResponse(
            status_code=status_code,
            content={"jsonrpc": "2.0", "error": {"code": -32001, "message": message}},
            headers={"Retry-After": str(AUTH_FAILURE_WINDOW_SECONDS)} if status_code == 429 else None,
        )

    try:
        within_agent_limit = await _allow_limited_request(
            [("agent", str(agent_info["agent_id"]))],
            AGENT_RATE_LIMIT_REQUESTS,
            RATE_LIMIT_WINDOW_SECONDS,
        )
    except SharedStateUnavailable:
        logger.exception("Shared state unavailable during agent rate limiting")
        return JSONResponse(status_code=503, content={"jsonrpc": "2.0", "error": {
            "code": -32002, "message": "Agent rate limiting unavailable",
        }})
    if not within_agent_limit:
        from database import SessionLocal

        event = _append_auth_event(
            category="rate_limited",
            source_ip=source_ip,
            key_prefix=key_prefix,
            agent_id=agent_info["agent_id"],
        )
        audit_db = None
        try:
            audit_db = SessionLocal()
            _persist_auth_event(
                audit_db,
                category="rate_limited",
                source_ip=source_ip,
                key_prefix=key_prefix,
                agent_id=agent_info["agent_id"],
            )
            audit_db.commit()
        except Exception:
            if audit_db is not None:
                audit_db.rollback()
            logger.error("Failed to persist agent traffic limit event")
        finally:
            if audit_db is not None:
                audit_db.close()
        await traffic_broadcaster.broadcast({"type": "authentication_event", "data": dict(event)})
        return JSONResponse(
            status_code=429,
            content={"jsonrpc": "2.0", "error": {"code": -32002, "message": "Agent rate limit exceeded"}},
            headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )

    request.state.agent_identity = agent_info
    logger.info("Authenticated agent id=%s key_prefix=%s", agent_info["agent_id"], key_prefix)

    async def emit_interception_event(event: dict) -> None:
        safe_event = {
            "type": "mcp_event",
            "data": {
                key: event.get(key) for key in (
                    "schema_version", "event_id", "timestamp", "session_id", "request_id",
                    "agent_id", "agent_name", "environment", "direction", "method",
                    "upstream_server", "tool_name", "arguments", "resource_uri", "prompt_name",
                    "decision", "decision_reason", "matched_rule_ids", "latency_ms",
                    "response_status", "response_size_bytes", "source_ip", "payload_hash", "payload",
                    "rule_risk_score", "decision_source", "sqli_findings", "ml_score",
                )
            },
        }
        event_arguments = event.get("arguments")
        behavioral_params = {
            key: value
            for key, value in (event_arguments.items() if isinstance(event_arguments, dict) else [])
            if key in {"path", "command", "sql"}
        }
        behavioral_anomaly, _ = behavioral_monitor.add_request(
            str(agent_info["agent_id"]),
            {
                "timestamp": event["timestamp"],
                "method": event["method"],
                "params": behavioral_params,
                "tool_name": event.get("tool_name"),
                "decision": event.get("decision", "allow"),
                **_argument_shape(event_arguments),
            },
        )
        safe_event["data"]["ml_anomaly"] = behavioral_anomaly
        if behavioral_anomaly:
            from database import MCPRequestEvent, SessionLocal

            db = SessionLocal()
            try:
                persisted_event = db.query(MCPRequestEvent).filter_by(
                    event_id=event["event_id"],
                ).first()
                if persisted_event is not None:
                    persisted_payload = json.loads(persisted_event.payload_json)
                    persisted_payload["behavioral_anomaly"] = True
                    persisted_event.payload_json = json.dumps(persisted_payload, ensure_ascii=False)
                    db.commit()
            except Exception:
                db.rollback()
                logger.exception(
                    "Failed to persist behavioral anomaly event_id=%s",
                    event["event_id"],
                )
            finally:
                db.close()
        payload_data = event.get("payload", {})
        sqli_analysis = payload_data.get("sqli_analysis", {}) if isinstance(payload_data, dict) else {}
        sqli_findings = sqli_analysis.get("findings", []) if isinstance(sqli_analysis, dict) else []
        is_sqli_alert = bool(sqli_findings) and event.get("decision") in {"block", "flag"}
        request_log.append({
            "event_id": event["event_id"],
            "timestamp": event["timestamp"],
            "agent_id": agent_info["name"],
            "method": event["method"],
            "params": event.get("payload", {}),
            "policy_allowed": event["decision"] != "block",
            "policy_reason": event["decision_reason"],
            "event_category": "security" if event["decision"] == "block" or is_sqli_alert else "system",
        })
        if is_sqli_alert:
            indicator_ids = list(dict.fromkeys(item.get("id", "SQLI-UNKNOWN") for item in sqli_findings))
            reason = "SQL injection indicators: " + ", ".join(indicator_ids[:4])
            severity_order = {"low": 1, "medium": 2, "high": 3}
            highest = max(
                (item.get("severity", "low").lower() for item in sqli_findings),
                key=lambda value: severity_order.get(value, 0),
                default="low",
            )
            alert = create_or_update_alert(
                agent_id=agent_info["name"],
                alert_type="rule_based",
                reason=reason,
                severity=highest.upper(),
                request_data={
                    "method": event.get("method"),
                    "tool_name": event.get("tool_name"),
                    "sqli_findings": sqli_findings,
                    "decision_source": event.get("decision_source", "rule"),
                },
                event_id=event["event_id"],
                decision=event["decision"].upper(),
            )
            alert["rule_id"] = indicator_ids[0] if indicator_ids else "SQLI-UNKNOWN"
            alert["risk"]["rule_score"] = round(float(sqli_analysis.get("rule_risk_score", 0.0)) * 100)
            alert["risk"]["score"] = max(alert["risk"]["score"], alert["risk"]["rule_score"])
            alert["evidence"]["rule"] = alert["rule_id"]
            alert["evidence"]["sqli_findings"] = sqli_findings
            alert["evidence"]["explanation"] = reason
        queued = await asyncio.to_thread(update_outbox_payload, event["event_id"], safe_event)
        if not queued:
            await traffic_broadcaster.broadcast(safe_event)

    return await mcp_interception.intercept_request(request, agent_info, emit_interception_event)


@app.get("/mcp/events", tags=["MCP Proxy"], summary="Query redacted MCP interception events")
async def list_mcp_events(
    agent_id: int | None = None,
    decision: str | None = None,
    method: str | None = None,
    tool_name: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
):
    from database import MCPRequestEvent, SessionLocal

    if decision is not None and decision not in {"allow", "block", "flag"}:
        raise HTTPException(status_code=422, detail="decision must be allow, block, or flag")
    if since is not None and until is not None and since > until:
        raise HTTPException(status_code=422, detail="since must not be later than until")
    db = SessionLocal()
    try:
        query = db.query(MCPRequestEvent)
        if agent_id is not None:
            query = query.filter(MCPRequestEvent.agent_id == agent_id)
        if decision is not None:
            query = query.filter(MCPRequestEvent.decision == decision)
        if method is not None:
            query = query.filter(MCPRequestEvent.method == method)
        if tool_name is not None:
            query = query.filter(MCPRequestEvent.tool_name == tool_name)
        if since is not None:
            since_utc = since.astimezone(timezone.utc).replace(tzinfo=None) if since.tzinfo else since
            query = query.filter(MCPRequestEvent.timestamp >= since_utc)
        if until is not None:
            until_utc = until.astimezone(timezone.utc).replace(tzinfo=None) if until.tzinfo else until
            query = query.filter(MCPRequestEvent.timestamp <= until_utc)
        events = query.order_by(MCPRequestEvent.timestamp.desc(), MCPRequestEvent.id.desc()).limit(
            max(1, min(limit, 500))
        ).all()
        serialized_events = []
        for event in events:
            payload = json.loads(event.payload_json)
            serialized_events.append({
                "schema_version": event.schema_version,
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat() + "Z",
                "session_id": event.session_id,
                "request_id": event.request_id,
                "agent_id": event.agent_id,
                "agent_name": event.agent_name,
                "environment": event.environment,
                "direction": event.direction,
                "method": event.method,
                "upstream_server": event.upstream_server,
                "tool_name": event.tool_name,
                "resource_uri": event.resource_uri,
                "prompt_name": event.prompt_name,
                "decision": event.decision,
                "decision_reason": event.decision_reason,
                "matched_rule_ids": json.loads(event.matched_rule_ids),
                "latency_ms": event.latency_ms,
                "response_status": event.response_status,
                "response_size_bytes": event.response_size_bytes,
                "source_ip": event.source_ip,
                "payload_hash": event.payload_hash,
                "payload": payload,
                "rule_risk_score": event.rule_risk_score,
                "decision_source": event.decision_source,
                "ml_anomaly": payload.get("behavioral_anomaly", False),
                "ml_score": payload.get("ml_score"),
            })
        return {"events": serialized_events}
    finally:
        db.close()

# ============ WEBSOCKET: LIVE TRAFFIC ============
@app.websocket("/mcp/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    """
    WebSocket endpoint for real-time MCP traffic updates
    Pushes new events as they happen
    """
    offered_protocols = websocket.scope.get("subprotocols", [])
    ticket_protocol = next(
        (value for value in offered_protocols if value.startswith("cybereye-ticket.")),
        None,
    )
    ticket = ticket_protocol.removeprefix("cybereye-ticket.") if ticket_protocol else ""
    try:
        operator_id = await get_shared_state().consume_ws_ticket(ticket) if ticket else None
    except SharedStateUnavailable:
        logger.exception("Shared state unavailable while validating WebSocket ticket")
        await websocket.close(code=1013, reason="Operator authentication unavailable")
        return
    if operator_id is None:
        await websocket.close(code=4401, reason="Operator authentication required")
        return

    if not await traffic_broadcaster.connect(websocket):
        await websocket.close(code=4429, reason="Live traffic connection limit reached")
        return
    logger.info("Authenticated operator connected to live traffic feed")

    try:
        # Send aggregate-only bootstrap data; per-event logs wait for the private filter.
        await websocket.send_json({
            "type": "snapshot",
            "data": {
                "total_requests": len(request_log),
                "total_blocked": len(blocked_requests),
                "total_anomalies": len(anomaly_alerts),
                "total_system_events": len(system_events),
            },
            "timestamp": datetime.now().isoformat(),
        })
        # Filters remain local to this gateway and are never published to Redis.
        control_times: deque[float] = deque()
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                now = time.monotonic()
                control_times.append(now)
                while control_times and now - control_times[0] >= 60:
                    control_times.popleft()
                if len(control_times) > WS_CONTROL_RATE or len(data.encode("utf-8")) > WS_MAX_CONTROL_BYTES:
                    await websocket.close(code=4429, reason="Live traffic control rate or size limit exceeded")
                    break
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
                    continue
                try:
                    control = json.loads(data)
                except json.JSONDecodeError:
                    await websocket.close(code=4400, reason="Invalid live traffic control message")
                    break
                if not isinstance(control, dict) or control.get("type") != "subscribe":
                    await websocket.close(code=4400, reason="Unsupported live traffic control message")
                    break
                try:
                    filters = await traffic_broadcaster.subscribe(websocket, control.get("filters", {}))
                except ValueError as exc:
                    await websocket.send_json({"type": "subscription_error", "message": str(exc)})
                    continue
                await websocket.send_json({"type": "subscription_updated", "filters": filters})
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "heartbeat"})
                except:
                    break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await traffic_broadcaster.disconnect(websocket)


# ============ CYBEREYE ENDPOINTS ============
@app.post("/cybereye/analyze", tags=["CyberEye"])
async def cybereye_analyze(request: Request):
    body = await request.body()
    data = json.loads(body)

    input_type = data.get("type", "")
    input_data = data.get("data", "")

    if not input_type or not input_data:
        return {
            "error": "Missing type or data",
            "available_types": ["url", "file", "network", "user", "android", "password", "qr"]
        }

    if input_type == "file" and isinstance(input_data, dict):
        content = input_data.get("content")
        if isinstance(content, str) and len(content.encode("utf-8")) > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File content exceeds the 10 MB scan limit")

    results = cybereye.analyze(input_type, input_data)
    response = {
        "input_type": input_type,
        "results": results,
        "risk_score": cybereye.get_risk_score()
    }
    if input_type == "password":
        password_analyzer = cybereye.modules.get("PasswordAnalyzer")
        if password_analyzer is None:
            raise HTTPException(status_code=503, detail="Password analysis module is unavailable")
        password_analysis = password_analyzer.assess_password(input_data)
        response["risk_score"] = password_analysis["risk_score"]
        response["analysis"] = password_analysis

    return response


@app.get("/cybereye/events", tags=["CyberEye"])
async def cybereye_events(limit: int = 50):
    return {
        "events": cybereye.get_all_events(limit),
        "total": len(cybereye.events)
    }


@app.get("/cybereye/alerts", tags=["CyberEye"])
async def cybereye_alerts(limit: int = 20):
    return {
        "alerts": cybereye.get_recent_alerts(limit),
        "total": len(cybereye.events)
    }


@app.get("/cybereye/stats", tags=["CyberEye"])
async def cybereye_stats():
    return cybereye.get_module_stats()


@app.get("/cybereye/risk", tags=["CyberEye"])
async def cybereye_risk():
    return {
        "risk_score": cybereye.get_risk_score(),
        "total_events": len(cybereye.events)
    }


# ============ MONITORING ENDPOINTS ============
@app.get("/health", tags=["Monitoring"])
async def health_check():
    return {
        "status": "healthy",
        "requests_processed": len(request_log),
        "blocked": len(blocked_requests),
        "anomalies": len(anomaly_alerts),
        "ml_models": len(behavioral_monitor.models),
        "policies": "active",
        "cybereye_modules": len(cybereye.modules),
        "auth_enabled": True,
        "websocket_connections": len(traffic_broadcaster.active_connections),
    }


@app.post("/api/ml/score", tags=["Monitoring"], summary="Score a payload using the Random Forest payload model")
async def score_ml_payload(request: Request):
    payload = await request.json()
    text = payload.get("payload") if isinstance(payload, dict) else payload
    result = score_payload(text)
    return result


@app.get("/api/ml/model-info", tags=["Monitoring"], summary="Model version, thresholds, and current health")
async def model_info():
    info = get_model_info()
    return {
        "loaded": info["model_loaded"],
        "fallback": info["fallback"],
        "model_version": info["model_version"],
        "metrics": info["metrics"],
        "thresholds": info["thresholds"],
        "status": "fallback" if info["fallback"] else "loaded",
    }


@app.put("/api/ml/thresholds", tags=["Monitoring"], summary="Adjust the ML decision thresholds")
async def update_ml_thresholds(request: Request):
    operator = getattr(request.state, "operator_identity", None)
    scopes = set(operator.get("scopes", [])) if operator else set()
    if "gateway:write" not in scopes:
        raise HTTPException(status_code=403, detail="Operator scope gateway:write required")
    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON object required")
    warn = float(payload.get("warn", 0.50))
    block = float(payload.get("block", 0.85))
    if warn >= block:
        raise HTTPException(status_code=400, detail="warn threshold must be lower than block")
    os.environ["CYBEREYE_WARN_THRESHOLD"] = str(warn)
    os.environ["CYBEREYE_BLOCK_THRESHOLD"] = str(block)
    from ml import config

    config.WARN_THRESHOLD = warn
    config.BLOCK_THRESHOLD = block
    return {"warn": warn, "block": block, "status": "updated"}


@app.get("/api/ml/network-flow/model-info", tags=["Monitoring"], summary="Network-flow model health and test metrics")
async def network_flow_model_info():
    return get_network_flow_model_info()


@app.post("/api/ml/network-flow/score", tags=["Monitoring"], summary="Score a CSV of UNSW-NB15-compatible network flows")
async def score_network_flow(request: Request):
    content = await request.body()
    try:
        return score_network_flow_csv(content)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/logs", tags=["Monitoring"])
async def get_logs(limit: int = 50):
    return {
        "total": len(request_log),
        "blocked": len(blocked_requests),
        "anomalies": len(anomaly_alerts),
        "logs": request_log[-limit:]
    }


@app.get("/logs/blocked", tags=["Monitoring"])
async def get_blocked_logs(limit: int = 50):
    return {
        "total": len(blocked_requests),
        "logs": blocked_requests[-limit:]
    }


@app.get("/logs/anomalies", tags=["Monitoring"])
async def get_anomalies(limit: int = 50):
    return {
        "total": len(anomaly_alerts),
        "alerts": anomaly_alerts[-limit:]
    }


@app.patch("/logs/anomalies/{alert_id}/status", tags=["Monitoring"], summary="Update an alert investigation status")
async def update_alert_status(alert_id: str, status: str):
    allowed_statuses = {"NEW", "ACKNOWLEDGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"}
    normalized_status = status.upper()
    if normalized_status not in allowed_statuses:
        raise HTTPException(status_code=422, detail=f"Status must be one of: {', '.join(sorted(allowed_statuses))}")
    alert = next((item for item in anomaly_alerts if item["id"] == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert["status"] = normalized_status
    alert["updated_at"] = utcnow().isoformat()
    return alert


@app.get("/logs/system", tags=["Monitoring"])
async def get_system_events(limit: int = 50):
    """Operational and protocol events, kept separate from threats."""
    return {
        "total": len(system_events),
        "events": system_events[-limit:]
    }


@app.get("/stats", tags=["Monitoring"])
async def get_stats():
    from sqlalchemy import case, func
    sqli_blocks_by_hour = {}
    sqli_block_count = 0
    from database import MCPRequestEvent, SessionLocal

    now = utcnow().astimezone(timezone.utc)
    start = (now - timedelta(hours=24)).replace(tzinfo=None)
    db = SessionLocal()
    try:
        total = db.query(func.count(MCPRequestEvent.id)).scalar() or 0
        blocked = db.query(func.count(MCPRequestEvent.id)).filter(
            MCPRequestEvent.decision == "block"
        ).scalar() or 0
        method_counts = dict(
            db.query(MCPRequestEvent.method, func.count(MCPRequestEvent.id))
            .group_by(MCPRequestEvent.method)
            .all()
        )
        decision_events = db.query(
            MCPRequestEvent.decision,
            MCPRequestEvent.matched_rule_ids,
            MCPRequestEvent.decision_reason,
            MCPRequestEvent.decision_source,
            MCPRequestEvent.sqli_findings_json,
            MCPRequestEvent.payload_json,
        ).filter(MCPRequestEvent.decision.in_(("block", "flag"))).all()

        categories = {
            "SQL injection": 0,
            "Path traversal": 0,
            "Tool policy violations": 0,
            "ML payload detections": 0,
            "Protocol validation": 0,
            "Behavioral anomalies": 0,
            "Other gateway rules": 0,
        }
        for event in decision_events:
            try:
                rule_ids = json.loads(event.matched_rule_ids or "[]")
            except (TypeError, ValueError):
                rule_ids = []
            rule_ids = [item for item in rule_ids if isinstance(item, str)] if isinstance(rule_ids, list) else []
            try:
                findings = json.loads(event.sqli_findings_json or "[]")
            except (TypeError, ValueError):
                findings = []
            try:
                payload = json.loads(event.payload_json or "{}")
            except (TypeError, ValueError):
                payload = {}
            payload = payload if isinstance(payload, dict) else {}
            reason = (event.decision_reason or "").lower()
            categorized = False
            if payload.get("behavioral_anomaly"):
                categories["Behavioral anomalies"] += 1
                categorized = True
            if "model" in (event.decision_source or "").lower() or any(
                rule_id.startswith("MODEL-PAYLOAD") for rule_id in rule_ids
            ):
                categories["ML payload detections"] += 1
                categorized = True
            if (isinstance(findings, list) and findings) or any(
                rule_id.startswith("SQLI-") for rule_id in rule_ids
            ):
                categories["SQL injection"] += 1
                categorized = True
            if "PATH_TRAVERSAL" in rule_ids or any(
                phrase in reason for phrase in ("path traversal", "sensitive path")
            ):
                categories["Path traversal"] += 1
                categorized = True
            if "BASE-ALLOWED-TOOLS" in rule_ids or any(
                phrase in reason for phrase in ("allowed_tools", "disallowed tool")
            ):
                categories["Tool policy violations"] += 1
                categorized = True
            if any(rule_id in {
                "BASE-METHOD-DIRECTION", "BASE-UNKNOWN-METHOD", "BASE-CONFIG-ERROR",
                "GATEWAY-INVALID-REQUEST",
            } for rule_id in rule_ids) or any(
                phrase in reason for phrase in ("protocol", "malformed", "invalid json-rpc")
            ):
                categories["Protocol validation"] += 1
                categorized = True
            if not categorized:
                categories["Other gateway rules"] += 1

        traffic_hours = db.query(
            func.strftime("%Y-%m-%dT%H:00:00Z", MCPRequestEvent.timestamp),
            func.count(MCPRequestEvent.id),
            func.sum(case((MCPRequestEvent.decision == "block", 1), else_=0)),
        ).filter(
            MCPRequestEvent.timestamp >= start,
        ).group_by(
            func.strftime("%Y-%m-%dT%H:00:00Z", MCPRequestEvent.timestamp),
        ).order_by(
            func.strftime("%Y-%m-%dT%H:00:00Z", MCPRequestEvent.timestamp),
        ).all()
        traffic_by_hour = [
            {"hour": hour, "events": count, "blocked": blocked_count or 0}
            for hour, count, blocked_count in traffic_hours
        ]

        sqli_events = db.query(
            MCPRequestEvent.timestamp,
            MCPRequestEvent.matched_rule_ids,
        ).filter(
            MCPRequestEvent.timestamp >= start,
            MCPRequestEvent.decision == "block",
            MCPRequestEvent.matched_rule_ids.like("%SQLI-%"),
        ).order_by(MCPRequestEvent.timestamp.asc()).all()
        for event in sqli_events:
            try:
                rule_ids = json.loads(event.matched_rule_ids or "[]")
            except (TypeError, ValueError):
                rule_ids = []
            if not any(isinstance(rule_id, str) and rule_id.startswith("SQLI-") for rule_id in rule_ids):
                continue
            sqli_block_count += 1
            hour = event.timestamp.replace(minute=0, second=0, microsecond=0).isoformat() + "Z"
            sqli_blocks_by_hour[hour] = sqli_blocks_by_hour.get(hour, 0) + 1
    finally:
        db.close()

    return {
        "total_requests": total,
        "blocked": blocked,
        "block_rate": round((blocked / total * 100) if total > 0 else 0, 2),
        "anomaly_alerts": len(decision_events),
        "system_events": len(system_events),
        "sqli_blocks_24h": sqli_block_count,
        "sqli_blocks_by_hour": [
            {"hour": hour, "blocks": count}
            for hour, count in sorted(sqli_blocks_by_hour.items())
        ],
        "ml_models": len(behavioral_monitor.models),
        "detection_categories": categories,
        "traffic_by_hour": traffic_by_hour,
        "methods": method_counts,
        "monitor_stats": {
            "total_requests": total,
            "anomalies_detected": categories["Behavioral anomalies"],
            "agents_monitored": len(behavioral_monitor.models),
            "total_alerts": len(decision_events),
        },
        "performance": performance_snapshot(),
    }


@app.get("/metrics", tags=["Monitoring"], summary="Gateway performance telemetry")
async def get_metrics():
    """Latency, error-rate, throughput, and rate-limit metrics."""
    return performance_snapshot()


@app.get("/agent/{agent_id}", tags=["Monitoring"])
async def get_agent_stats(agent_id: str):
    return behavioral_monitor.get_agent_stats(agent_id)


@app.get("/agents/summary", tags=["Monitoring"], summary="Agent security and behavior summaries")
async def get_agents_summary():
    """Summarize persistent MCP events, falling back to legacy gateway logs."""
    from database import MCPRequestEvent, SessionLocal

    summaries = {}
    db = SessionLocal()
    try:
        events = db.query(MCPRequestEvent).order_by(
            MCPRequestEvent.timestamp.asc(), MCPRequestEvent.id.asc()
        ).all()
        for event in events:
            agent_id = str(event.agent_id)
            item = summaries.setdefault(agent_id, {
                "agent_id": agent_id, "requests": 0, "blocked": 0, "anomalies": 0,
                "tools": {}, "last_seen": None, "recent_events": [],
            })
            item["requests"] += 1
            item["blocked"] += int(event.decision in {"block", "flag"})
            try:
                payload = json.loads(event.payload_json or "{}")
            except (TypeError, ValueError):
                payload = {}
            anomaly = bool(payload.get("behavioral_anomaly") or payload.get("analysis_anomaly"))
            item["anomalies"] += int(anomaly)
            method = event.tool_name or event.method or "unknown"
            item["tools"][method] = item["tools"].get(method, 0) + 1
            item["last_seen"] = event.timestamp.isoformat() + "Z"
    finally:
        db.close()

    # Legacy request telemetry is still useful for agents that have not yet
    # sent MCP traffic through the persisted interception pipeline.
    if not summaries:
        for log in request_log:
            agent_id = str(log.get("agent_id", "unknown"))
            item = summaries.setdefault(agent_id, {
                "agent_id": agent_id, "requests": 0, "blocked": 0, "anomalies": 0,
                "tools": {}, "last_seen": None, "recent_events": [],
            })
            item["requests"] += 1
            item["blocked"] += int(
                not bool(log.get("policy_allowed", False))
                or bool(log.get("analysis_anomaly"))
                or bool(log.get("ml_anomaly"))
            )
            item["anomalies"] += int(bool(log.get("analysis_anomaly") or log.get("ml_anomaly")))
            method = log.get("method", "unknown")
            item["tools"][method] = item["tools"].get(method, 0) + 1
            item["last_seen"] = log.get("timestamp")

    agents = []
    for item in summaries.values():
        blocked_rate = item["blocked"] / item["requests"] if item["requests"] else 0
        risk_score = min(100, round(item["anomalies"] * 25 + blocked_rate * 45 + min(len(item["tools"]), 10) * 2))
        item["risk_score"] = risk_score
        item["trust_level"] = "QUARANTINED" if risk_score >= 80 else "RESTRICTED" if risk_score >= 60 else "MONITORED" if risk_score >= 30 else "TRUSTED"
        item["behavior_status"] = "ANOMALOUS" if item["anomalies"] else "NORMAL"
        agents.append(item)
    return {"total_agents": len(agents), "agents": sorted(agents, key=lambda item: item["risk_score"], reverse=True)}


# ============ ROOT ============
@app.get("/", tags=["Monitoring"], summary="API service overview")
async def root():
    return {
        "service": "Sentinel-MCP Gateway",
        "version": "2.0.0",
        "auth_required": True,
        "documentation": {
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_schema": "/openapi.json",
        },
        "websocket": "ws://localhost:8001/mcp/ws/traffic",
        "endpoints": {
            "auth": {
                "register": "/auth/register (POST)",
                "login": "/auth/login (POST)",
                "refresh": "/auth/refresh (POST)",
                "logout": "/auth/logout (POST)",
                "me": "/auth/me (GET)"
            },
            "mcp": {
                "proxy": "/mcp/proxy (POST) [REQUIRES API KEY]",
                "websocket": "/mcp/ws/traffic (WS)",
                "overview": "/mcp/overview (GET)",
                "agents": "/mcp/agents (GET/POST)",
                "agent_detail": "/mcp/agents/{id} (GET/DELETE)",
                "agent_suspend": "/mcp/agents/{id}/suspend (POST)",
                "agent_resume": "/mcp/agents/{id}/resume (POST)",
                "servers": "/mcp/servers (GET/POST)",
                "server_health": "/mcp/servers/{id}/health (POST)",
                "policies": "/mcp/policies (GET/POST)",
                "policy_toggle": "/mcp/policies/{id}/toggle (PUT)"
            },
            "ml": {
                "health": "/ml/health (GET)",
                "scan_qr": "/ml/scan/qr (POST)",
                "analyze_url": "/ml/analyze/url (POST)"
            },
            "monitoring": {
                "health": "/health (GET)",
                "stats": "/stats (GET)",
                "logs": "/logs (GET)",
                "logs_blocked": "/logs/blocked (GET)",
                "logs_anomalies": "/logs/anomalies (GET)",
                "agent": "/agent/{id} (GET)"
            },
            "cybereye": {
                "analyze": "/cybereye/analyze (POST)",
                "events": "/cybereye/events (GET)",
                "alerts": "/cybereye/alerts (GET)",
                "stats": "/cybereye/stats (GET)",
                "risk": "/cybereye/risk (GET)"
            }
        }
    }


if __name__ == "__main__":
    print("Starting Sentinel-MCP Gateway v2.0")
    print("Security Policies: ENABLED")
    print("ML Anomaly Detection: ENABLED")
    print("CyberEye Modules: ENABLED")
    print(f"   - {len(cybereye.modules)} modules loaded")
    print("Authentication: ENABLED")
    print("MCP Management: ENABLED")
    print("API Key Auth: ENABLED (for /mcp/proxy)")
    print("WebSocket Live Traffic: ENABLED")
    print("ML QR Scanner: ENABLED")
    print("Listening on http://localhost:8001")
    print("")
    print("Implements:")
    print("   - SECUREVENT (arXiv 2606.01741) hybrid approach")
    print("   - CyberEye 11-module security platform")
    print("   - Rule-based policies (layer 1)")
    print("   - Behavioral analysis (layer 2)")
    print("   - ML anomaly detection (layer 3)")
    print("   - JWT Authentication (layer 4)")
    print("   - API Key Auth (layer 5)")
    print("   - MCP Management (layer 6)")
    print("   - WebSocket Live Traffic (layer 7)")
    uvicorn.run(app, host="0.0.0.0", port=8001)
