"""
Phishing Detection Module
Classifies URLs as malicious or safe using rule-based + ML
"""

import re
import hashlib
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
from ..base_module import SecurityModule, SecurityEvent

class PhishingDetector(SecurityModule):
    """Detects phishing URLs using multiple techniques"""
    
    def __init__(self):
        super().__init__("PhishingDetector", "detection")
        
        # Known malicious domains (simplified - in production, use threat intel feeds)
        self.malicious_domains = {
            "malicious-example.com",
            "phishing-site.net",
            "fake-bank.org",
            "secure-login.xyz"
        }
        
        # Suspicious keywords in URLs
        self.suspicious_keywords = [
            "login", "verify", "update", "confirm", "secure",
            "account", "banking", "paypal", "amazon", "apple",
            "microsoft", "google", "facebook", "instagram"
        ]
        
        # TLDs commonly used in phishing
        self.suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".club"}
        
        # URL patterns for credential harvesting
        self.credential_patterns = [
            r"login.*callback",
            r"signin.*redirect",
            r"auth.*token",
            r"password.*reset",
            r"verify.*identity"
        ]
        
        self.config = {
            "min_confidence": 0.6,
            "check_domain_age": False,  # Would need WHOIS API
            "check_ssl": True,
            "check_url_shorteners": True
        }
    
    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "input_types": ["url", "link"],
            "detection_methods": [
                "domain_blacklist",
                "keyword_analysis",
                "tld_analysis",
                "pattern_matching",
                "url_structure_analysis"
            ],
            "output": "phishing_score + confidence"
        }
    
    def analyze(self, input_data: Any) -> Optional[SecurityEvent]:
        """Analyze a URL for phishing indicators"""
        if isinstance(input_data, str):
            url = input_data
        elif isinstance(input_data, dict) and "url" in input_data:
            url = input_data["url"]
        else:
            return None
        
        try:
            result = self._analyze_url(url)
            
            if result["score"] > 0.5:  # Threshold for alert
                severity = "HIGH" if result["score"] > 0.8 else "MEDIUM"
                return self.generate_event(
                    event_type="phishing_url_detected",
                    severity=severity,
                    description=f"Phishing URL detected: {url[:50]}...",
                    data={
                        "url": url,
                        "score": result["score"],
                        "confidence": result["confidence"],
                        "indicators": result["indicators"],
                        "matched_patterns": result["matched_patterns"]
                    },
                    confidence=result["confidence"]
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}")
            return None
    
    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Internal URL analysis"""
        score = 0.0
        indicators = []
        matched_patterns = []
        confidence = 0.0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            full_url = url.lower()
            
            # 1. Check domain blacklist
            if domain in self.malicious_domains or any(d in domain for d in self.malicious_domains):
                score += 0.8
                indicators.append("domain_in_blacklist")
                confidence = 0.9
            
            # 2. Check for suspicious TLDs
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    score += 0.3
                    indicators.append(f"suspicious_tld_{tld}")
                    confidence = max(confidence, 0.6)
                    break
            
            # 3. Check for suspicious keywords
            keyword_count = 0
            for keyword in self.suspicious_keywords:
                if keyword in full_url:
                    keyword_count += 1
                    indicators.append(f"keyword_{keyword}")
            
            if keyword_count >= 3:
                score += 0.4
                confidence = max(confidence, 0.7)
            elif keyword_count >= 2:
                score += 0.2
                confidence = max(confidence, 0.5)
            
            # 4. Check credential patterns
            for pattern in self.credential_patterns:
                if re.search(pattern, full_url, re.IGNORECASE):
                    score += 0.3
                    matched_patterns.append(pattern)
                    indicators.append("credential_pattern")
                    confidence = max(confidence, 0.7)
            
            # 5. Check for IP address in domain (common in phishing)
            ip_pattern = r'\d+\.\d+\.\d+\.\d+'
            if re.search(ip_pattern, domain):
                score += 0.4
                indicators.append("ip_address_in_url")
                confidence = max(confidence, 0.6)
            
            # 6. Check for excessive subdomains (often phishing)
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                score += 0.2
                indicators.append("excessive_subdomains")
            
            # 7. Check URL length (phishing often uses long URLs)
            if len(url) > 200:
                score += 0.2
                indicators.append("long_url")
            
            # 8. Check for port numbers (unusual)
            if ':' in domain and not domain.startswith('['):
                score += 0.3
                indicators.append("port_in_url")
                confidence = max(confidence, 0.5)
            
            # Normalize score
            score = min(score, 1.0)
            confidence = min(confidence + 0.2, 1.0)  # Base confidence
            
            # If no strong indicators, low confidence
            if confidence < 0.1 and score < 0.3:
                confidence = 0.3
            
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return {
                "score": 0.0,
                "confidence": 0.0,
                "indicators": ["parse_error"],
                "matched_patterns": []
            }
        
        return {
            "score": score,
            "confidence": confidence,
            "indicators": indicators,
            "matched_patterns": matched_patterns
        }