"""
Sentinel-MCP Gateway - AI/ML Security Monitoring Framework
Complete with Security Policies + Behavioral Anomaly Detection
"""

from fastapi import FastAPI, Request
import uvicorn
import json
import logging
from datetime import datetime
from policies import PolicyEngine, PolicyAction
from monitor import BehavioralMonitor, RequestAnalyzer
from fastapi.middleware.cors import CORSMiddleware

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Sentinel-MCP Gateway", version="2.0.0")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
policy_engine = PolicyEngine()
behavioral_monitor = BehavioralMonitor(window_size=100, contamination=0.1)
request_analyzer = RequestAnalyzer()

# Track requests
request_log = []
blocked_requests = []
anomaly_alerts = []

@app.post("/mcp")
async def mcp_proxy(request: Request):
    """
    Main MCP proxy endpoint - evaluates requests with policies + ML anomaly detection
    """
    body = await request.body()
    
    try:
        data = json.loads(body)
    except:
        data = {"raw": body.decode()}
    
    method = data.get("method", "unknown")
    params = data.get("params", {})
    agent_id = data.get("agent_id", "default-agent")  # Simulated agent ID
    
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

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "requests_processed": len(request_log),
        "blocked": len(blocked_requests),
        "anomalies": len(anomaly_alerts),
        "ml_models": len(behavioral_monitor.models),
        "policies": "active"
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

if __name__ == "__main__":
    print("🚀 Starting Sentinel-MCP Gateway v2.0")
    print("🔒 Security Policies: ENABLED")
    print("🧠 ML Anomaly Detection: ENABLED")
    print("📡 Listening on http://localhost:8000")
    print("📊 Stats: http://localhost:8000/stats")
    print("📋 Logs: http://localhost:8000/logs")
    print("🚨 Anomalies: http://localhost:8000/logs/anomalies")
    print("")
    print("💡 This implements SECUREVENT (arXiv 2606.01741) hybrid approach")
    print("   - Rule-based policies (first layer)")
    print("   - Behavioral analysis (second layer)")
    print("   - ML anomaly detection (third layer)")
    uvicorn.run(app, host="0.0.0.0", port=8000)