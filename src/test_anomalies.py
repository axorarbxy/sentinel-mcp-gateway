"""
Test Behavioral Anomaly Detection
Simulates normal agent behavior then introduces anomalies
"""

import httpx
import json
import time
import random

def send_mcp_request(method, params=None, agent_id="test-agent"):
    """Send MCP request with agent_id"""
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": int(time.time()),
        "agent_id": agent_id
    }
    
    response = httpx.post("http://localhost:8000/mcp", json=payload)
    return response.json()

def simulate_normal_agent(agent_id, iterations=20):
    """Simulate a normal agent with regular behavior"""
    print(f"🤖 Simulating normal agent: {agent_id}")
    print(f"   {iterations} iterations...")
    
    operations = [
        ("filesystem/read", {"path": "/home/user/test.txt"}),
        ("filesystem/read", {"path": "/home/user/config.json"}),
        ("shell/execute", {"command": "ls"}),
        ("shell/execute", {"command": "pwd"}),
        ("db/query", {"sql": "SELECT * FROM users"})
    ]
    
    for i in range(iterations):
        method, params = random.choice(operations)
        result = send_mcp_request(method, params, agent_id)
        
        if "error" in result:
            print(f"  {i+1}. ❌ {method} - BLOCKED")
        else:
            print(f"  {i+1}. ✅ {method} - ALLOWED")
        
        time.sleep(0.5)  # Normal pacing

def simulate_anomalous_agent(agent_id, iterations=20):
    """Simulate an agent that suddenly behaves anomalously"""
    print(f"🤖 Simulating ANOMALOUS agent: {agent_id}")
    print(f"   {iterations} iterations...")
    
    # Phase 1: Normal behavior (first 10 iterations)
    print("  Phase 1: Normal behavior...")
    normal_ops = [
        ("filesystem/read", {"path": "/home/user/test.txt"}),
        ("shell/execute", {"command": "ls"}),
        ("db/query", {"sql": "SELECT * FROM users"})
    ]
    
    for i in range(10):
        method, params = random.choice(normal_ops)
        result = send_mcp_request(method, params, agent_id)
        print(f"  {i+1}. ✅ {method} - ALLOWED")
        time.sleep(0.3)
    
    # Phase 2: Anomalous behavior (sudden burst of suspicious requests)
    print("  Phase 2: ANOMALOUS behavior...")
    anomalous_ops = [
        # Rapid fire requests
        ("filesystem/read", {"path": "/etc/passwd"}),
        ("filesystem/read", {"path": "/etc/shadow"}),
        ("filesystem/read", {"path": "/root/secret.txt"}),
        ("shell/execute", {"command": "rm -rf /tmp/*"}),
        ("shell/execute", {"command": "cat /etc/passwd"}),
        ("db/query", {"sql": "DROP TABLE users"}),
        ("db/query", {"sql": "DELETE FROM users WHERE 1=1"}),
        # Unknown methods
        ("unknown/malicious", {"cmd": "evil"}),
        ("network/request", {"url": "192.168.1.1"})
    ]
    
    for i, (method, params) in enumerate(anomalous_ops):
        result = send_mcp_request(method, params, agent_id)
        if "error" in result:
            print(f"  {i+11}. ❌ {method} - BLOCKED (anomaly detected!)")
        else:
            print(f"  {i+11}. ⚠️ {method} - ALLOWED (missed anomaly)")
        time.sleep(0.1)  # Very fast = suspicious

if __name__ == "__main__":
    print("=" * 60)
    print("🧪 TESTING BEHAVIORAL ANOMALY DETECTION")
    print("=" * 60)
    
    # Test 1: Normal agent
    print("\n📝 TEST 1: Normal Agent Behavior")
    print("-" * 40)
    simulate_normal_agent("normal-agent", 15)
    
    # Wait a moment
    print("\n⏳ Training ML model...")
    time.sleep(2)
    
    # Test 2: Anomalous agent
    print("\n📝 TEST 2: Anomalous Agent Behavior")
    print("-" * 40)
    simulate_anomalous_agent("anomalous-agent", 20)
    
    print("\n" + "=" * 60)
    print("✅ Testing complete!")
    print("📊 Check stats: http://localhost:8000/stats")
    print("🚨 Check anomalies: http://localhost:8000/logs/anomalies")
    print("📋 Check agent stats: http://localhost:8000/agent/anomalous-agent")