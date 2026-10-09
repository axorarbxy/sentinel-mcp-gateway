"""
Password Strength Analysis Module
Checks password entropy and patterns
"""

import re
import math
from typing import Dict, Any, Optional
from ..base_module import SecurityModule, SecurityEvent

class PasswordAnalyzer(SecurityModule):
    """Analyzes password strength and security"""
    
    def __init__(self):
        super().__init__("PasswordAnalyzer", "utility")
        
        # Common weak passwords
        self.common_passwords = {
            "password", "123456", "12345678", "qwerty", "abc123",
            "password123", "admin", "letmein", "welcome", "monkey",
            "dragon", "master", "sunshine", "iloveyou", "princess"
        }
        
        # Character sets for entropy calculation
        self.char_sets = {
            "lowercase": 26,
            "uppercase": 26,
            "digits": 10,
            "symbols": 33,
            "space": 1
        }
        
        self.config = {
            "min_length": 8,
            "require_uppercase": True,
            "require_digits": True,
            "require_symbols": True,
            "min_entropy": 40  # bits
        }
    
    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "input_types": ["password_string"],
            "detection_methods": [
                "entropy_calculation",
                "pattern_matching",
                "common_password_check",
                "character_analysis"
            ],
            "output": "strength_score + entropy"
        }
    
    def analyze(self, input_data: Any) -> Optional[SecurityEvent]:
        """Analyze password strength"""
        try:
            if not isinstance(input_data, str) and not isinstance(input_data, dict):
                return None
            
            password = input_data if isinstance(input_data, str) else input_data.get("password", "")
            
            if not password:
                return None
            
            result = self._analyze_password(password)
            
            if result["is_weak"]:
                return self.generate_event(
                    event_type="weak_password_detected",
                    severity="MEDIUM",
                    description="Weak password detected",
                    data={
                        "password": password[:2] + "*" * (len(password) - 4) + password[-2:] if len(password) > 4 else "****",
                        "score": result["score"],
                        "entropy": result["entropy"],
                        "issues": result["issues"],
                        "strength": result["strength"]
                    },
                    confidence=0.85
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error analyzing password: {e}")
            return None
    
    def _analyze_password(self, password: str) -> Dict[str, Any]:
        """Internal password analysis"""
        issues = []
        score = 100  # Start with perfect score
        entropy = 0
        
        # 1. Check length
        length = len(password)
        if length < 8:
            issues.append("Too short (< 8 characters)")
            score -= 30
        elif length < 12:
            score -= 10
        
        # 2. Check character variety
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9\s]', password))
        
        if not has_lower:
            issues.append("No lowercase letters")
            score -= 10
        if not has_upper:
            issues.append("No uppercase letters")
            score -= 15
        if not has_digit:
            issues.append("No digits")
            score -= 15
        if not has_symbol:
            issues.append("No symbols")
            score -= 20
        
        # 3. Check for common passwords
        if password.lower() in self.common_passwords:
            issues.append("Common/weak password")
            score -= 50
        
        # 4. Calculate entropy
        char_set_size = 0
        if has_lower:
            char_set_size += self.char_sets["lowercase"]
        if has_upper:
            char_set_size += self.char_sets["uppercase"]
        if has_digit:
            char_set_size += self.char_sets["digits"]
        if has_symbol:
            char_set_size += self.char_sets["symbols"]
        
        if char_set_size > 0:
            entropy = length * math.log2(char_set_size)
        
        if entropy < 30:
            issues.append("Low entropy")
            score -= 20
        elif entropy < 40:
            issues.append("Medium-low entropy")
            score -= 10
        
        # 5. Check for patterns
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            issues.append("Repeated characters")
            score -= 10
        
        if re.search(r'(123|abc|qwerty|admin|password)', password.lower()):
            issues.append("Common pattern detected")
            score -= 15
        
        # Normalize score
        score = max(0, min(100, score))
        
        # Determine strength
        if score >= 80:
            strength = "Strong"
        elif score >= 60:
            strength = "Medium"
        else:
            strength = "Weak"
        
        return {
            "score": score / 100,  # Normalize to 0-1
            "entropy": entropy,
            "issues": issues,
            "strength": strength,
            "is_weak": score < 60
        }