"""
QR Code Safety Checker
Scans QR codes for malicious payloads
"""

import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from ..base_module import SecurityModule, SecurityEvent

class QRSafetyChecker(SecurityModule):
    """Checks QR codes for malicious content"""
    
    def __init__(self):
        super().__init__("QRSafetyChecker", "utility")
        
        # Suspicious patterns in QR content
        self.suspicious_patterns = {
            "url_shortener": [
                "bit.ly", "tinyurl", "goo.gl", "ow.ly", "is.gd",
                "buff.ly", "shorturl", "tiny.cc", "tr.im"
            ],
            "malicious_keywords": [
                "login", "verify", "update", "secure", "confirm",
                "account", "banking", "paypal", "amazon", "apple"
            ],
            "suspicious_tlds": [
                ".tk", ".ml", ".ga", ".cf", ".top", ".xyz"
            ]
        }
        
        self.config = {
            "check_urls": True,
            "check_suspicious_tlds": True,
            "check_shorteners": True,
            "check_malicious_keywords": True
        }
    
    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "input_types": ["qr_content", "url", "text"],
            "detection_methods": [
                "url_analysis",
                "pattern_matching",
                "domain_checking",
                "content_analysis"
            ],
            "output": "safety_score + risk_level"
        }
    
    def analyze(self, input_data: Any) -> Optional[SecurityEvent]:
        """Analyze QR code content for safety"""
        try:
            if not isinstance(input_data, str) and not isinstance(input_data, dict):
                return None
            
            content = input_data if isinstance(input_data, str) else input_data.get("content", "")
            
            if not content:
                return None
            
            result = self._analyze_content(content)
            
            if result["is_suspicious"]:
                return self.generate_event(
                    event_type="suspicious_qr_detected",
                    severity=result["severity"],
                    description="Suspicious QR code content detected",
                    data={
                        "content": content[:100] + ("..." if len(content) > 100 else ""),
                        "score": result["score"],
                        "indicators": result["indicators"],
                        "risk_level": result["risk_level"]
                    },
                    confidence=result["confidence"]
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error analyzing QR code: {e}")
            return None
    
    def _analyze_content(self, content: str) -> Dict[str, Any]:
        """Internal QR content analysis"""
        indicators = []
        score = 0.0
        confidence = 0.3
        severity = "LOW"
        
        # Check if it's a URL
        is_url = content.startswith(("http://", "https://"))
        
        if is_url:
            # URL analysis
            parsed = urlparse(content)
            domain = parsed.netloc.lower()
            
            # Check for URL shorteners
            for shortener in self.suspicious_patterns["url_shortener"]:
                if shortener in domain:
                    indicators.append(f"url_shortener_{shortener}")
                    score += 0.4
                    confidence = max(confidence, 0.6)
                    severity = "MEDIUM"
                    break
            
            # Check for suspicious TLDs
            for tld in self.suspicious_patterns["suspicious_tlds"]:
                if domain.endswith(tld):
                    indicators.append(f"suspicious_tld_{tld}")
                    score += 0.3
                    confidence = max(confidence, 0.5)
                    severity = "MEDIUM"
            
            # Check for malicious keywords in domain
            for keyword in self.suspicious_patterns["malicious_keywords"]:
                if keyword in domain:
                    indicators.append(f"keyword_{keyword}")
                    score += 0.2
                    confidence = max(confidence, 0.4)
            
            # Check for IP address in URL
            if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
                indicators.append("ip_address_in_url")
                score += 0.3
                confidence = max(confidence, 0.5)
                severity = "MEDIUM"
        
        else:
            # Non-URL content
            # Check for suspicious patterns
            if any(p in content.lower() for p in ["password", "login", "verify", "confirm"]):
                indicators.append("suspicious_text_pattern")
                score += 0.3
                confidence = max(confidence, 0.4)
            
            # Check for encoded/obfuscated content
            if len(content) > 100 and not any(c.isprintable() for c in content):
                indicators.append("encoded_content")
                score += 0.4
                confidence = max(confidence, 0.6)
                severity = "MEDIUM"
        
        # Normalize
        score = min(score, 1.0)
        confidence = min(confidence, 0.9)
        
        if score > 0.7:
            severity = "HIGH"
        elif score > 0.4:
            severity = "MEDIUM"
        
        return {
            "score": score,
            "confidence": confidence,
            "indicators": indicators,
            "is_suspicious": score > 0.3,
            "severity": severity,
            "risk_level": "HIGH" if score > 0.7 else "MEDIUM" if score > 0.4 else "LOW"
        }