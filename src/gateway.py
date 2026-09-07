"""
Sentinel-MCP Gateway - AI/ML Security Monitoring Framework
Base MCP Proxy Server
"""

from fastapi import FastAPI, Request, Response
import uvicorn
import json
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Sentinel-MCP Gateway", version="1.0.0")

# Track requests for monitoring
request_log = []

@app.post("/mcp")
async def mcp_proxy(request: Request):
    """
    Main MCP proxy endpoint - intercepts all MCP requests
    """
    # Get the raw request body
    body = await request.body()
    
    # Parse JSON
    try:
        data = json.loads(body)
    except:
        data = {"raw": body.decode()}
    
    # Log the request for monitoring
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "method": data.get("method", "unknown"),
        "params": data.get("params", {}),
        "id": data.get("id")
    }
    request_log.append(log_entry)
    
    # Log to console
    logger.info(f"📥 MCP Request: {data.get('method')}")
    logger.info(f"   Params: {data.get('params')}")
    
    # TODO: 
    # 1. Policy validation
    # 2. Anomaly detection
    # 3. MITRE ATLAS mapping
    # 4. Forward to actual MCP server
    
    # For now, return a test response
    return {
        "jsonrpc": "2.0",
        "id": data.get("id"),
        "result": {
            "status": "monitored",
            "message": "Request intercepted by Sentinel-MCP"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "requests_processed": len(request_log)}

@app.get("/logs")
async def get_logs():
    """View recent request logs"""
    return {"logs": request_log[-50:]}  # Return last 50 requests

if __name__ == "__main__":
    print("🚀 Starting Sentinel-MCP Gateway...")
    print("📡 Listening on http://localhost:8000")
    print("📊 Health check: http://localhost:8000/health")
    print("📋 Logs: http://localhost:8000/logs")
    uvicorn.run(app, host="0.0.0.0", port=8000)