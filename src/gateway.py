"""
Sentinel-MCP Gateway - AI/ML Security Monitoring Framework
Complete with Security Policies + ML Anomaly Detection + CyberEye Modules + Authentication + MCP Management + API Key Auth + WebSocket
"""

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from typing import DefaultDict, Set
import asyncio
import uvicorn
import json
import logging
import uuid
import os
import time
from collections import defaultdict, deque
from datetime import datetime

# Import components
from policies import PolicyEngine, PolicyAction
from monitor import BehavioralMonitor, RequestAnalyzer
from modules.module_manager import ModuleManager
from gateway_plugins import GatewayPluginManager

# Import auth routes
from auth_routes import router as auth_router

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
    title="Sentinel-MCP Gateway API",
    summary="Runtime security and monitoring for AI agents using MCP.",
    description="""
## Sentinel-MCP API

Use this API to register MCP agents, enforce policy checks on tool calls, and
inspect security, system, and behavioral-monitoring telemetry.

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

allowed_hosts = [host.strip() for host in os.getenv("SENTINEL_ALLOWED_HOSTS", "*").split(",") if host.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

RATE_LIMIT_REQUESTS = max(1, int(os.getenv("SENTINEL_RATE_LIMIT_REQUESTS", "60")))
RATE_LIMIT_WINDOW_SECONDS = max(1, int(os.getenv("SENTINEL_RATE_LIMIT_WINDOW_SECONDS", "60")))
rate_limit_buckets: DefaultDict[str, deque[float]] = defaultdict(deque)
rate_limit_lock = asyncio.Lock()
gateway_metrics = {
    "started_at": time.time(),
    "requests": 0,
    "errors": 0,
    "latencies_ms": deque(maxlen=1000),
    "status_codes": defaultdict(int),
    "rate_limited": 0,
}


@app.middleware("http")
async def gateway_security_and_metrics(request: Request, call_next):
    """Add traceability, proxy-safe headers, proxy rate limits, and telemetry."""
    request_id = request.headers.get("X-Request-ID", f"req_{uuid.uuid4().hex}")
    started = time.perf_counter()

    if request.url.path == "/mcp/proxy":
        key = request.headers.get("Authorization") or (request.client.host if request.client else "anonymous")
        now = time.monotonic()
        async with rate_limit_lock:
            bucket = rate_limit_buckets[key]
            while bucket and now - bucket[0] >= RATE_LIMIT_WINDOW_SECONDS:
                bucket.popleft()
            if len(bucket) >= RATE_LIMIT_REQUESTS:
                gateway_metrics["rate_limited"] += 1
                gateway_metrics["requests"] += 1
                gateway_metrics["status_codes"]["429"] += 1
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded", "request_id": request_id},
                    headers={
                        "Retry-After": str(RATE_LIMIT_WINDOW_SECONDS),
                        "X-Request-ID": request_id,
                        "X-Content-Type-Options": "nosniff",
                    },
                )
            bucket.append(now)

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
        "bearerFormat": "sk_sentinel API key",
        "description": "Use the API key generated when registering an MCP agent.",
    }
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_origin_regex=r"chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ INCLUDE AUTH ROUTES ============
app.include_router(auth_router)

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


def create_or_update_alert(
    *, agent_id: str, alert_type: str, reason: str, severity: str,
    request_data: dict, event_id: str, decision: str = "BLOCK", score=None,
):
    """Correlate equivalent detections while retaining each raw request log.

    An alert represents analyst work; request_log remains the immutable event
    stream. Matching agent, detection, tool and reason within five minutes are
    intentionally shown as one alert with an occurrence count.
    """
    now = datetime.utcnow()
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
    """Manages WebSocket connections for live traffic updates"""
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self.lock:
            self.active_connections.add(websocket)
        logger.info(f"🔌 WebSocket connected (total: {len(self.active_connections)})")

    async def disconnect(self, websocket: WebSocket):
        async with self.lock:
            self.active_connections.discard(websocket)
        logger.info(f"🔌 WebSocket disconnected (total: {len(self.active_connections)})")

    async def broadcast(self, message: dict):
        """Send message to all connected clients"""
        if not self.active_connections:
            return

        async with self.lock:
            connections = list(self.active_connections)

        dead_connections = set()
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"WebSocket send error: {e}")
                dead_connections.add(connection)

        # Clean up dead connections
        if dead_connections:
            async with self.lock:
                for conn in dead_connections:
                    self.active_connections.discard(conn)


# Global broadcaster instance
traffic_broadcaster = TrafficBroadcaster()


# ============ AUTH HELPER ============
def verify_agent_api_key(api_key: str):
    """
    Verify API key against registered MCP agents
    Returns: (agent_object, error_message)
    """
    from database import SessionLocal, MCPAgent

    if not api_key:
        return None, "Missing API key"

    try:
        db = SessionLocal()
        agent = db.query(MCPAgent).filter(MCPAgent.api_key == api_key).first()

        if not agent:
            db.close()
            return None, "Invalid API key"

        if not agent.is_active:
            db.close()
            return None, "Agent is suspended"

        # Return agent info (detach from session)
        agent_info = {
            "id": agent.id,
            "name": agent.name,
            "api_key": agent.api_key,
            "is_active": agent.is_active,
        }
        db.close()
        return agent_info, None

    except Exception as e:
        logger.error(f"API key verification error: {e}")
        return None, f"Authentication error: {str(e)}"


# ============ MCP PROXY ENDPOINT (AUTHENTICATED) ============
@app.post(
    "/mcp/proxy",
    tags=["MCP Proxy"],
    summary="Validate and enforce an MCP tool call",
    openapi_extra={
        "security": [{"MCPAgentKey": []}],
        "requestBody": {"required": True, "content": {"application/json": {"example": {
            "jsonrpc": "2.0", "id": "req_001", "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "README.md"}},
        }}}},
    },
)
async def mcp_proxy(request: Request):
    """
    Main MCP proxy endpoint - REQUIRES API KEY AUTHENTICATION
    Header: Authorization: Bearer sk_sentinel_xxxxx
    """
    from database import SessionLocal, MCPAgent

    # ============ STEP 1: AUTHENTICATION ============
    auth_header = request.headers.get("Authorization", "")

    if not auth_header:
        logger.warning("🚫 Request rejected: Missing Authorization header")
        return JSONResponse(
            status_code=401,
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32001,
                    "message": "Unauthorized",
                    "data": {
                        "reason": "Missing Authorization header",
                        "hint": "Add header: Authorization: Bearer sk_sentinel_xxxxx"
                    }
                }
            }
        )

    # Check Bearer format
    if not auth_header.startswith("Bearer "):
        logger.warning("🚫 Request rejected: Invalid Authorization format")
        return JSONResponse(
            status_code=401,
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32001,
                    "message": "Unauthorized",
                    "data": {
                        "reason": "Invalid Authorization format",
                        "hint": "Expected: Bearer sk_sentinel_xxxxx"
                    }
                }
            }
        )

    api_key = auth_header.replace("Bearer ", "").strip()

    # Verify against database
    agent_info, error = verify_agent_api_key(api_key)

    if error:
        logger.warning(f"🚫 Request rejected: {error}")
        return JSONResponse(
            status_code=401,
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32001,
                    "message": "Unauthorized",
                    "data": {
                        "reason": error
                    }
                }
            }
        )

    # Authenticated ✅
    logger.info(f"✅ Authenticated: Agent '{agent_info['name']}' (ID: {agent_info['id']})")

    # ============ STEP 2: PROCESS REQUEST ============
    body = await request.body()

    try:
        data = json.loads(body)
    except:
        data = {"raw": body.decode()}

    method = data.get("method", "unknown")
    params = data.get("params", {})
    # Use agent name from DB (not from request body)
    agent_id = agent_info["name"]
    await gateway_plugins.emit("mcp.request_received", {
        "request_id": request.headers.get("X-Request-ID"),
        "agent_id": agent_id,
        "method": method,
    })

    # 1. Policy evaluation (rule-based)
    policy_result = policy_engine.evaluate(method, params)
    # Malformed MCP calls are operational/protocol failures.  They are still
    # denied, but are not automatically security threats or ML alerts.
    is_protocol_error = any(
        detail["rule"] == "ACL" and detail["reason"] == "Missing tool name in request"
        for detail in policy_result.details
    )
    event_category = "system" if is_protocol_error else "security"

    # 2. Request analysis (rule-based anomaly detection)
    request_data = {
        "timestamp": datetime.now().isoformat(),
        "method": method,
        "params": params,
        "agent_id": agent_id
    }
    analysis_result = request_analyzer.analyze(agent_id, request_data)

    # 3. Behavioral monitoring (ML-based anomaly detection)
    is_ml_anomaly, ml_alert = behavioral_monitor.add_request(agent_id, request_data)

    # Log the request
    log_entry = {
        "event_id": f"evt_{uuid.uuid4().hex}",
        "timestamp": datetime.now().isoformat(),
        "agent_id": agent_id,
        "method": method,
        "params": params,
        "id": data.get("id"),
        "policy_allowed": policy_result.allowed,
        "policy_reason": policy_result.reason,
        "analysis_anomaly": analysis_result["anomaly"],
        "analysis_reason": analysis_result["reason"],
        "ml_anomaly": is_ml_anomaly,
        "event_category": event_category,
    }
    request_log.append(log_entry)

    # Determine if request should be blocked
    should_block = False
    block_reasons = []

    # Check policy
    if not policy_result.allowed:
        should_block = True
        block_reasons.append(f"Policy: {policy_result.reason}")

    # Check rule-based analysis
    if analysis_result["anomaly"]:
        should_block = True
        block_reasons.append(f"Rule-based: {analysis_result['reason']}")
        if not is_protocol_error:
            create_or_update_alert(
                agent_id=agent_id, alert_type="rule_based",
                reason=analysis_result["reason"], severity=analysis_result["severity"],
                request_data=request_data, event_id=log_entry["event_id"],
            )

    # Check ML-based anomaly
    if is_ml_anomaly:
        should_block = True
        block_reasons.append(f"ML-based: Behavioral anomaly detected")
        if ml_alert and not is_protocol_error:
            create_or_update_alert(
                agent_id=agent_id, alert_type="ml_based",
                reason="Behavioral pattern deviation", severity="MEDIUM",
                request_data=request_data, event_id=log_entry["event_id"],
                score=ml_alert.get("score"),
            )

    # A request may violate multiple controls, but it is only one blocked
    # request.  Appending here prevents impossible block rates above 100%.
    if should_block:
        blocked_requests.append(log_entry)
        if is_protocol_error:
            system_events.append({
                **log_entry,
                "system_code": "MCP-VAL-001",
                "system_reason": "Missing required MCP tool name",
            })

    await gateway_plugins.emit("mcp.decision", {
        "event_id": log_entry["event_id"],
        "agent_id": agent_id,
        "method": method,
        "allowed": not should_block,
        "category": event_category,
        "reasons": block_reasons,
    })

    # ============ UPDATE AGENT COUNTERS IN DATABASE ============
    try:
        db = SessionLocal()
        agent = db.query(MCPAgent).filter(MCPAgent.id == agent_info["id"]).first()

        if agent:
            agent.total_requests = (agent.total_requests or 0) + 1
            if should_block:
                agent.blocked_requests = (agent.blocked_requests or 0) + 1
            agent.last_seen = datetime.utcnow()
            db.commit()
            logger.info(f"📊 Updated counters for agent '{agent.name}': total={agent.total_requests}, blocked={agent.blocked_requests}")
    except Exception as e:
        logger.error(f"Failed to update agent counters: {e}")
    finally:
        try:
            db.close()
        except:
            pass

    # Log decision
    if should_block:
        logger.warning(f"❌ BLOCKED: {method} - {'; '.join(block_reasons)}")
    else:
        logger.info(f"✅ ALLOWED: {method} - {policy_result.reason}")

    # ============ BROADCAST TO WEBSOCKET CLIENTS ============
    try:
        event = {
            "type": "new_request",
            "data": {
                "timestamp": log_entry["timestamp"],
                "agent_id": agent_id,
                "method": method,
                "params": params,
                "allowed": not should_block,
                "event_id": log_entry["event_id"],
                "event_category": event_category,
                "reason": policy_result.reason if not should_block else "; ".join(block_reasons),
                "ml_anomaly": is_ml_anomaly,
                "total_requests": len(request_log),
                "total_blocked": len(blocked_requests),
                "total_anomalies": len(anomaly_alerts),
                "total_system_events": len(system_events),
            },
            "timestamp": datetime.now().isoformat(),
        }
        await traffic_broadcaster.broadcast(event)
    except Exception as e:
        logger.error(f"Broadcast error: {e}")

    # Return response
    if should_block:
        return {
            "jsonrpc": "2.0",
            "id": data.get("id"),
            "error": {
                "code": -32000,
                "message": "Security violation",
                "data": {
                    "reasons": block_reasons,
                    "policy_details": policy_result.details,
                    "analysis_details": analysis_result
                }
            }
        }

    return {
        "jsonrpc": "2.0",
        "id": data.get("id"),
        "result": {
            "status": "allowed",
            "message": "Request allowed by Sentinel-MCP",
            "policy_reason": policy_result.reason,
            "analysis": analysis_result
        }
    }


# ============ WEBSOCKET: LIVE TRAFFIC ============
@app.websocket("/mcp/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    """
    WebSocket endpoint for real-time MCP traffic updates
    Pushes new events as they happen
    """
    await traffic_broadcaster.connect(websocket)

    try:
        # Send initial snapshot on connect
        await websocket.send_json({
            "type": "snapshot",
            "data": {
                "total_requests": len(request_log),
                "total_blocked": len(blocked_requests),
                "total_anomalies": len(anomaly_alerts),
                "total_system_events": len(system_events),
                "recent_logs": request_log[-10:],
            },
            "timestamp": datetime.now().isoformat(),
        })

        # Keep connection alive
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "heartbeat"})
                except:
                    break

    except WebSocketDisconnect:
        await traffic_broadcaster.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
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

    results = cybereye.analyze(input_type, input_data)

    return {
        "input_type": input_type,
        "results": results,
        "risk_score": cybereye.get_risk_score()
    }


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
    alert["updated_at"] = datetime.utcnow().isoformat()
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
    total = len(request_log)
    blocked = len(blocked_requests)

    method_counts = {}
    for log in request_log:
        method = log.get("method", "unknown")
        method_counts[method] = method_counts.get(method, 0) + 1

    return {
        "total_requests": total,
        "blocked": blocked,
        "block_rate": round((blocked / total * 100) if total > 0 else 0, 2),
        "anomaly_alerts": len(anomaly_alerts),
        "system_events": len(system_events),
        "ml_models": len(behavioral_monitor.models),
        "methods": method_counts,
        "monitor_stats": behavioral_monitor.get_stats(),
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
    """One consistent view of agent activity derived from retained gateway events."""
    summaries = {}
    for log in request_log:
        agent_id = log.get("agent_id", "unknown")
        item = summaries.setdefault(agent_id, {
            "agent_id": agent_id, "requests": 0, "blocked": 0, "anomalies": 0,
            "tools": {}, "last_seen": None, "recent_events": [],
        })
        item["requests"] += 1
        is_blocked = not log.get("policy_allowed", False) or log.get("analysis_anomaly") or log.get("ml_anomaly")
        item["blocked"] += int(is_blocked)
        item["anomalies"] += int(log.get("analysis_anomaly", False) or log.get("ml_anomaly", False))
        method = log.get("method", "unknown")
        item["tools"][method] = item["tools"].get(method, 0) + 1
        item["last_seen"] = log.get("timestamp")
        item["recent_events"].append(log)

    agents = []
    for item in summaries.values():
        item["recent_events"] = item["recent_events"][-10:]
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
    print("🚀 Starting Sentinel-MCP Gateway v2.0")
    print("🔒 Security Policies: ENABLED")
    print("🧠 ML Anomaly Detection: ENABLED")
    print("🛡️ CyberEye Modules: ENABLED")
    print(f"   - {len(cybereye.modules)} modules loaded")
    print("🔐 Authentication: ENABLED")
    print("🎛️ MCP Management: ENABLED")
    print("🔑 API Key Auth: ENABLED (for /mcp/proxy)")
    print("📡 WebSocket Live Traffic: ENABLED")
    print("🤖 ML QR Scanner: ENABLED")
    print("📡 Listening on http://localhost:8001")
    print("")
    print("💡 Implements:")
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
