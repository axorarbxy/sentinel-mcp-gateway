"""
Test MCP Client - Simulates AI Agent making MCP calls
"""

import httpx
import json
import time

def send_mcp_request(method, params=None):
    """Send a mock MCP request to the gateway"""
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": int(time.time())
    }
    
    response = httpx.post("http://localhost:8000/mcp", json=payload)
    return response.json()

if __name__ == "__main__":
    print("🧪 Sending test MCP requests...")
    print("=" * 50)
    
    # Test 1: Read file
    result1 = send_mcp_request("filesystem/read", {"path": "/home/user/test.txt"})
    print(f"📄 File read response: {result1}")
    print("-" * 50)
    
    # Test 2: Execute command
    result2 = send_mcp_request("shell/execute", {"command": "ls -la"})
    print(f"💻 Command response: {result2}")
    print("-" * 50)
    
    # Test 3: Database query
    result3 = send_mcp_request("db/query", {"sql": "SELECT * FROM users"})
    print(f"🗄️ Database response: {result3}")
    print("=" * 50)
    print("✅ All tests complete!")