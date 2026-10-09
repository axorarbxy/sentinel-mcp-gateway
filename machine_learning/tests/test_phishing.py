"""
Test Phishing Detection API
"""

import requests
import json

test_urls = [
    'https://google.com/search',
    'https://github.com/explore',
    'https://secure-login.xyz/verify',
    'https://paypa1-secure.com/update',
    'https://paypal.com/signin',
    'https://web.whatsapp.com',
    'https://amaz0n-verify.top/login',
    'https://google.verify-account.tk/login',
]

print("=" * 70)
print("PHISHING DETECTION API TEST")
print("=" * 70)

for url in test_urls:
    try:
        r = requests.post(
            'http://localhost:8001/ml/analyze/url',
            json={'url': url},
            timeout=10
        )
        data = r.json()
        status = 'PHISHING' if data['is_suspicious'] else 'SAFE'
        risk = data['risk_score'] * 100
        factors = ', '.join(data['risk_factors'])
        print(f"\n{status:10s} {url}")
        print(f"   Risk: {risk:.1f}%")
        print(f"   Factors: {factors}")
    except Exception as e:
        print(f"\nERROR {url}: {e}")

print("\n" + "=" * 70)