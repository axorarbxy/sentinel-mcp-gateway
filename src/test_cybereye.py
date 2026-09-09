"""
Test CyberEye Module Integration
"""

import httpx
import json
import time

def test_cybereye_analysis():
    """Test CyberEye analysis endpoints"""
    
    print("🧪 Testing CyberEye Module Integration")
    print("=" * 60)
    
    # Test cases
    test_cases = [
        {
            "type": "url",
            "data": "http://malicious-example.com/login/verify"
        },
        {
            "type": "password",
            "data": "password123"
        },
        {
            "type": "password",
            "data": "SecureP@ssw0rd!2024"
        },
        {
            "type": "qr",
            "data": "https://bit.ly/3xYz123"
        },
        {
            "type": "network",
            "data": {
                "src_ip": "192.168.1.100",
                "dst_ip": "203.0.113.1",
                "dst_port": 22,
                "protocol": "TCP",
                "payload": "failed login attempt"
            }
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n📝 Test {i}: {test['type']}")
        print("-" * 40)
        
        try:
            response = httpx.post(
                "http://localhost:8000/cybereye/analyze",
                json=test,
                timeout=5.0
            )
            
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                
                if results:
                    for result in results:
                        print(f"  🔔 {result.get('module')}: {result.get('severity')}")
                        print(f"     {result.get('description')}")
                        print(f"     Confidence: {result.get('confidence', 0)}")
                else:
                    print("  ✅ No security issues detected")
            else:
                print(f"  ❌ Error: {response.status_code}")
                print(f"     {response.text}")
                
        except Exception as e:
            print(f"  ❌ Request failed: {e}")
    
    print("\n" + "=" * 60)
    print("✅ Testing complete!")

if __name__ == "__main__":
    test_cybereye_analysis()