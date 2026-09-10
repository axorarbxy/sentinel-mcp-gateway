"""
Sentinel-MCP Gateway - AI/ML Security Monitoring Framework
Complete with Security Policies + ML Anomaly Detection + CyberEye Modules + Authentication + MCP Management
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
import logging
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

# ============ MCP PROXY ENDPOINT ============
@app.post("/mcp/proxy")
async def mcp_proxy(request: Request):
    """
    Main MCP proxy endpoint - evaluates requests with policies + ML anomaly detection
    Note: Using /mcp/proxy to avoid conflict with /mcp/agents etc.
    """
    body = await request.body()
    
    try:
        data = json.loads(body)
    except:
        data = {"raw": body.decode()}
    
    method = data.get("method", "unknown")
    params = data.get("params", {})
    agent_id = data.get("agent_id", "default-agent")
    
    # 1. Policy evaluation (rule-based)
    policy_result = policy_engine.evaluate(method, params)
    
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
        "timestamp": datetime.now().isoformat(),
        "agent_id": agent_id,
        "method": method,
        "params": params,
        "id": data.get("id"),
        "policy_allowed": policy_result.allowed,
        "policy_reason": policy_result.reason,
        "analysis_anomaly": analysis_result["anomaly"],
        "analysis_reason": analysis_result["reason"],
        "ml_anomaly": is_ml_anomaly
    }
    request_log.append(log_entry)
    
    # Determine if request should be blocked
    should_block = False
    block_reasons = []
    
    # Check policy
    if not policy_result.allowed:
        should_block = True
        block_reasons.append(f"Policy: {policy_result.reason}")
        blocked_requests.append(log_entry)
    
    # Check rule-based analysis
    if analysis_result["anomaly"]:
        should_block = True
        block_reasons.append(f"Rule-based: {analysis_result['reason']}")
        blocked_requests.append(log_entry)
        anomaly_alerts.append({
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
        blocked_requests.append(log_entry)
        if ml_alert:
            anomaly_alerts.append({
                "timestamp": datetime.now().isoformat(),
                "agent_id": agent_id,
                "type": "ml_based",
                "reason": "Behavioral pattern deviation",
                "score": ml_alert.get("score"),
                "request": request_data
            })
    
    # Log decision
    if should_block:
        logger.warning(f"❌ BLOCKED: {method} - {'; '.join(block_reasons)}")
    else:
        logger.info(f"✅ ALLOWED: {method} - {policy_result.reason}")
    
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
        "cybereye_modules": len(cybereye.modules)
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
        "endpoints": {
            "auth": {
                "register": "/auth/register (POST)",
                "login": "/auth/login (POST)",
                "refresh": "/auth/refresh (POST)",
                "logout": "/auth/logout (POST)",
                "me": "/auth/me (GET)"
            },
            "mcp": {
                "proxy": "/mcp/proxy (POST)",
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
    print("🤖 ML QR Scanner: ENABLED")
    print("📡 Listening on http://localhost:8001")
    print("")
    print("📊 Dashboards:")
    print("   - Main: http://localhost:8001/")
    print("   - MCP Overview: http://localhost:8001/mcp/overview")
    print("   - MCP Agents: http://localhost:8001/mcp/agents")
    print("   - MCP Policies: http://localhost:8001/mcp/policies")
    print("   - MCP Servers: http://localhost:8001/mcp/servers")
    print("   - ML Health: http://localhost:8001/ml/health")
    print("")
    print("💡 Implements:")
    print("   - SECUREVENT (arXiv 2606.01741) hybrid approach")
    print("   - CyberEye 11-module security platform")
    print("   - Rule-based policies (layer 1)")
    print("   - Behavioral analysis (layer 2)")
    print("   - ML anomaly detection (layer 3)")
    print("   - JWT Authentication (layer 4)")
    print("   - MCP Management (layer 5)")
    uvicorn.run(app, host="0.0.0.0", port=8001)