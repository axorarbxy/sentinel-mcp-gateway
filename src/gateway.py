"""
Sentinel-MCP Gateway - AI/ML Security Monitoring Framework
Base MCP Proxy Server with Security Policies
"""

from fastapi import FastAPI, Request, Response
import uvicorn
import json
import logging
from datetime import datetime
from policies import PolicyEngine, PolicyResult, PolicyAction

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Sentinel-MCP Gateway", version="1.0.0")

# Initialize policy engine
policy_engine = PolicyEngine()

# Track requests for monitoring
request_log = []
blocked_requests = []

@app.post("/mcp")
async def mcp_proxy(request: Request):
    """
    Main MCP proxy endpoint - intercepts and evaluates all MCP requests
    """
    # Get the raw request body
    body = await request.body()
    
    # Parse JSON
    try:
        data = json.loads(body)
    except:
        data = {"raw": body.decode()}
    
    method = data.get("method", "unknown")
    params = data.get("params", {})
    
    # Evaluate against security policies
    policy_result = policy_engine.evaluate(method, params)
    
    # Log the request
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "method": method,
        "params": params,
        "id": data.get("id"),
        "policy_allowed": policy_result.allowed,
        "policy_reason": policy_result.reason,
        "policy_action": policy_result.action.value
    }
    request_log.append(log_entry)
    
    # Log to console
    if policy_result.allowed:
        logger.info(f"✅ ALLOW: {method} - {policy_result.reason}")
    else:
        logger.warning(f"❌ BLOCK: {method} - {policy_result.reason}")
        blocked_requests.append(log_entry)
    
    # Apply policy decision
    if policy_result.action == PolicyAction.BLOCK:
        return {
            "jsonrpc": "2.0",
            "id": data.get("id"),
            "error": {
                "code": -32000,
                "message": "Security policy violation",
                "data": {
                    "reason": policy_result.reason,
                    "details": policy_result.details
                }
            }
        }
    
    # If allowed, forward to actual MCP server
    # TODO: Implement actual forwarding to MCP servers
    return {
        "jsonrpc": "2.0",
        "id": data.get("id"),
        "result": {
            "status": "monitored_and_allowed",
            "message": "Request intercepted and approved by Sentinel-MCP",
            "policy_reason": policy_result.reason
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "requests_processed": len(request_log),
        "blocked_requests": len(blocked_requests),
        "policies_loaded": len(policy_engine.policies)
    }

@app.get("/logs")
async def get_logs(limit: int = 50):
    """View recent request logs"""
    return {
        "total": len(request_log),
        "blocked": len(blocked_requests),
        "logs": request_log[-limit:]
    }

@app.get("/logs/blocked")
async def get_blocked_logs(limit: int = 50):
    """View recent blocked requests only"""
    return {
        "total": len(blocked_requests),
        "logs": blocked_requests[-limit:]
    }

@app.get("/stats")
async def get_stats():
    """Get statistics about policy enforcement"""
    total = len(request_log)
    blocked = len(blocked_requests)
    
    if total == 0:
        block_rate = 0
    else:
        block_rate = (blocked / total) * 100
    
    # Count by method
    method_counts = {}
    for log in request_log:
        method = log.get("method", "unknown")
        method_counts[method] = method_counts.get(method, 0) + 1
    
    return {
        "total_requests": total,
        "blocked": blocked,
        "block_rate_percent": round(block_rate, 2),
        "methods": method_counts
    }

if __name__ == "__main__":
    print("🚀 Starting Sentinel-MCP Gateway...")
    print("📡 Listening on http://localhost:8000")
    print("📊 Health check: http://localhost:8000/health")
    print("📋 Logs: http://localhost:8000/logs")
    print("🚫 Blocked logs: http://localhost:8000/logs/blocked")
    print("📈 Stats: http://localhost:8000/stats")
    print("🔒 Security Policies ENABLED")
    uvicorn.run(app, host="0.0.0.0", port=8000)