"""
Test MCP Client - Tests security policies
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

def print_test(name, result):
    """Pretty print test results"""
    print(f"\n{'='*60}")
    print(f"🧪 TEST: {name}")
    print(f"{'='*60}")
    
    if "error" in result:
        print(f"❌ BLOCKED: {result['error']['data']['reason']}")
    else:
        print(f"✅ ALLOWED: {result.get('result', {}).get('policy_reason', 'No reason given')}")
    print(f"📝 Response: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    print("🔒 TESTING SECURITY POLICIES")
    print("=" * 60)
    
    # Test 1: Safe file read (should ALLOW)
    result1 = send_mcp_request("filesystem/read", {"path": "/home/user/test.txt"})
    print_test("Safe file read", result1)
    
    # Test 2: Sensitive file (should BLOCK)
    result2 = send_mcp_request("filesystem/read", {"path": "/etc/passwd"})
    print_test("Sensitive file access", result2)
    
    # Test 3: Path traversal (should BLOCK)
    result3 = send_mcp_request("filesystem/read", {"path": "../../../etc/shadow"})
    print_test("Path traversal", result3)
    
    # Test 4: Safe shell command (should ALLOW)
    result4 = send_mcp_request("shell/execute", {"command": "ls -la"})
    print_test("Safe shell command", result4)
    
    # Test 5: Dangerous shell command (should BLOCK)
    result5 = send_mcp_request("shell/execute", {"command": "rm -rf /"})
    print_test("Dangerous shell command", result5)
    
    # Test 6: Safe SQL query (should ALLOW)
    result6 = send_mcp_request("db/query", {"sql": "SELECT * FROM users WHERE id=1"})
    print_test("Safe SQL query", result6)
    
    # Test 7: Dangerous SQL (should BLOCK)
    result7 = send_mcp_request("db/query", {"sql": "DROP TABLE users"})
    print_test("Dangerous SQL", result7)
    
    # Test 8: Unknown method (should BLOCK)
    result8 = send_mcp_request("unknown/tool", {"arg": "value"})
    print_test("Unknown method", result8)
    
    print("\n" + "=" * 60)
    print("✅ All tests complete!")
    print(f"📊 Check stats at: http://localhost:8000/stats")
    print(f"📋 Check logs at: http://localhost:8000/logs")