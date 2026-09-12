"""
Sentinel-MCP Gateway - AI/ML Security Monitoring Framework
Complete with Security Policies + ML Anomaly Detection + CyberEye Modules + Authentication + MCP Management + API Key Auth + WebSocket
"""

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Set
import asyncio
import uvicorn
import json
import logging
import uuid
from datetime import datetime

# Import components
from policies import PolicyEngine, PolicyAction
from monitor import BehavioralMonitor, RequestAnalyzer
from modules.module_manager import ModuleManager

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
app = FastAPI(title="Sentinel-MCP Gateway", version="2.0.0")

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

# Initialize CyberEye modules
cybereye = ModuleManager()

# Track requests
request_log = []
blocked_requests = []
anomaly_alerts = []
system_events = []


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
@app.post("/mcp/proxy")
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
            anomaly_alerts.append({
                "event_id": log_entry["event_id"],
                "timestamp": datetime.now().isoformat(),
                "agent_id": agent_id,
                "type": "rule_based",
                "reason": analysis_result["reason"],
                "severity": analysis_result["severity"],
                "request": request_data
            })

    # Check ML-based anomaly
    if is_ml_anomaly:
        should_block = True
        block_reasons.append(f"ML-based: Behavioral anomaly detected")
        if ml_alert and not is_protocol_error:
            anomaly_alerts.append({
                "event_id": log_entry["event_id"],
                "timestamp": datetime.now().isoformat(),
                "agent_id": agent_id,
                "type": "ml_based",
                "reason": "Behavioral pattern deviation",
                "severity": "MEDIUM",
                "score": ml_alert.get("score"),
                "request": request_data
            })

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
@app.post("/cybereye/analyze")
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


@app.get("/cybereye/events")
async def cybereye_events(limit: int = 50):
    return {
        "events": cybereye.get_all_events(limit),
        "total": len(cybereye.events)
    }


@app.get("/cybereye/alerts")
async def cybereye_alerts(limit: int = 20):
    return {
        "alerts": cybereye.get_recent_alerts(limit),
        "total": len(cybereye.events)
    }


@app.get("/cybereye/stats")
async def cybereye_stats():
    return cybereye.get_module_stats()


@app.get("/cybereye/risk")
async def cybereye_risk():
    return {
        "risk_score": cybereye.get_risk_score(),
        "total_events": len(cybereye.events)
    }


# ============ MONITORING ENDPOINTS ============
@app.get("/health")
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


@app.get("/logs")
async def get_logs(limit: int = 50):
    return {
        "total": len(request_log),
        "blocked": len(blocked_requests),
        "anomalies": len(anomaly_alerts),
        "logs": request_log[-limit:]
    }


@app.get("/logs/blocked")
async def get_blocked_logs(limit: int = 50):
    return {
        "total": len(blocked_requests),
        "logs": blocked_requests[-limit:]
    }


@app.get("/logs/anomalies")
async def get_anomalies(limit: int = 50):
    return {
        "total": len(anomaly_alerts),
        "alerts": anomaly_alerts[-limit:]
    }


@app.get("/logs/system")
async def get_system_events(limit: int = 50):
    """Operational and protocol events, kept separate from threats."""
    return {
        "total": len(system_events),
        "events": system_events[-limit:]
    }


@app.get("/stats")
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
        "monitor_stats": behavioral_monitor.get_stats()
    }


@app.get("/agent/{agent_id}")
async def get_agent_stats(agent_id: str):
    return behavioral_monitor.get_agent_stats(agent_id)


# ============ ROOT ============
@app.get("/")
async def root():
    return {
        "service": "Sentinel-MCP Gateway",
        "version": "2.0.0",
        "auth_required": True,
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
