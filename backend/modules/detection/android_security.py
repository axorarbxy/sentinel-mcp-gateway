"""
Android App Security Analysis Module
Audits app permissions and checks for malicious behavior
"""

import re
import json
from typing import Dict, Any, Optional, List
from ..base_module import SecurityModule, SecurityEvent

class AndroidSecurityAnalyzer(SecurityModule):
    """Analyzes Android APKs for security issues"""
    
    def __init__(self):
        super().__init__("AndroidSecurityAnalyzer", "detection")
        
        # Dangerous permissions
        self.dangerous_permissions = {
            "READ_CONTACTS": "HIGH",
            "READ_SMS": "CRITICAL",
            "READ_CALL_LOG": "HIGH",
            "RECORD_AUDIO": "MEDIUM",
            "CAMERA": "MEDIUM",
            "ACCESS_FINE_LOCATION": "HIGH",
            "ACCESS_COARSE_LOCATION": "MEDIUM",
            "READ_EXTERNAL_STORAGE": "LOW",
            "WRITE_EXTERNAL_STORAGE": "MEDIUM",
            "READ_PHONE_STATE": "HIGH",
            "SEND_SMS": "CRITICAL",
            "CALL_PHONE": "HIGH",
            "READ_CALENDAR": "MEDIUM",
            "WRITE_CALENDAR": "MEDIUM",
            "GET_ACCOUNTS": "HIGH",
            "INTERNET": "LOW"
        }
        
        # Suspicious permission combinations
        self.suspicious_combos = [
            ["READ_SMS", "SEND_SMS", "INTERNET"],
            ["READ_CONTACTS", "INTERNET", "WRITE_EXTERNAL_STORAGE"],
            ["CAMERA", "RECORD_AUDIO", "INTERNET"],
            ["READ_PHONE_STATE", "READ_SMS", "INTERNET"],
            ["ACCESS_FINE_LOCATION", "INTERNET", "READ_EXTERNAL_STORAGE"]
        ]
        
        self.config = {
            "dangerous_permissions": self.dangerous_permissions,
            "suspicious_combos": self.suspicious_combos,
            "min_confidence": 0.5
        }
    
    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "input_types": ["apk_manifest", "permission_list", "app_metadata"],
            "detection_methods": [
                "permission_analysis",
                "permission_combination_analysis",
                "code_pattern_analysis",
                "behavioral_indicators"
            ],
            "output": "security_score + risk_level"
        }
    
    def analyze(self, input_data: Any) -> Optional[SecurityEvent]:
        """Analyze an Android app for security issues"""
        try:
            if isinstance(input_data, dict):
                return self._analyze_app_data(input_data)
            elif isinstance(input_data, list):
                return self._analyze_permissions(input_data)
            else:
                return None
        except Exception as e:
            logger.error(f"Error analyzing Android app: {e}")
            return None
    
    def _analyze_app_data(self, data: Dict) -> Optional[SecurityEvent]:
        """Analyze structured app data"""
        app_name = data.get("app_name", "Unknown App")
        permissions = data.get("permissions", [])
        
        return self._analyze_permissions(permissions, app_name)
    
    def _analyze_permissions(self, permissions: List[str], app_name: str = "Unknown App") -> Optional[SecurityEvent]:
        """Analyze a list of app permissions"""
        indicators = []
        score = 0.0
        confidence = 0.3
        high_risk_perms = []
        
        # Check each permission
        for perm in permissions:
            perm_upper = perm.upper()
            if perm_upper in self.dangerous_permissions:
                severity = self.dangerous_permissions[perm_upper]
                indicators.append(f"dangerous_permission_{perm}")
                high_risk_perms.append(perm)
                
                if severity == "CRITICAL":
                    score += 0.5
                    confidence = max(confidence, 0.8)
                elif severity == "HIGH":
                    score += 0.3
                    confidence = max(confidence, 0.6)
                elif severity == "MEDIUM":
                    score += 0.2
                    confidence = max(confidence, 0.4)
        
        # Check for suspicious combinations
        perm_set = set(p.upper() for p in permissions)
        for combo in self.suspicious_combos:
            if all(p in perm_set for p in combo):
                indicators.append(f"suspicious_combo_{'_'.join(combo[:2])}")
                score += 0.4
                confidence = max(confidence, 0.7)
        
        # Normalize score
        score = min(score, 1.0)
        confidence = min(confidence, 0.95)
        
        if score > 0.4:
            severity = "HIGH" if score > 0.7 else "MEDIUM"
            return self.generate_event(
                event_type="android_app_analysis",
                severity=severity,
                description=f"Suspicious app detected: {app_name}",
                data={
                    "app_name": app_name,
                    "permissions": permissions,
                    "high_risk_permissions": high_risk_perms,
                    "score": score,
                    "confidence": confidence,
                    "indicators": indicators
                },
                confidence=confidence
            )
        
        return None