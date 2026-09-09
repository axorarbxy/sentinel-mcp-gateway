"""
Insider Threat Detection Module
Flags anomalous behavior from internal users
"""

from typing import Dict, Any, Optional, List
from collections import defaultdict
from datetime import datetime, timedelta
from ..base_module import SecurityModule, SecurityEvent

class InsiderThreatDetector(SecurityModule):
    """Detects insider threats using behavioral analysis"""
    
    def __init__(self):
        super().__init__("InsiderThreatDetector", "detection")
        
        # User behavior tracking
        self.user_activity = defaultdict(list)  # user_id -> list of activities
        self.user_scores = defaultdict(float)
        self.user_baselines = defaultdict(dict)
        
        # Suspicious patterns
        self.suspicious_patterns = {
            "after_hours": (22, 6),  # 10 PM - 6 AM
            "weekend_access": [5, 6],  # Saturday, Sunday
            "large_download": 100,  # MB
            "high_frequency": 50,  # requests per hour
        }
        
        self.config = {
            "after_hours_start": 22,
            "after_hours_end": 6,
            "weekend_days": [5, 6],
            "large_download_threshold": 100,
            "high_frequency_threshold": 50,
            "learning_period": 7  # days
        }
    
    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "input_types": ["user_activity", "access_log", "data_transfer"],
            "detection_methods": [
                "behavioral_baselining",
                "anomaly_detection",
                "pattern_recognition",
                "risk_scoring"
            ],
            "output": "insider_risk_score"
        }
    
    def analyze(self, input_data: Any) -> Optional[SecurityEvent]:
        """Analyze user activity for insider threat indicators"""
        try:
            if not isinstance(input_data, dict):
                return None
            
            user_id = input_data.get("user_id")
            if not user_id:
                return None
            
            # Record activity
            self.user_activity[user_id].append(input_data)
            
            # Keep only recent activity
            cutoff = datetime.now() - timedelta(days=30)
            self.user_activity[user_id] = [
                a for a in self.user_activity[user_id]
                if datetime.fromisoformat(a.get("timestamp", datetime.now().isoformat())) > cutoff
            ]
            
            # Analyze for anomalies
            return self._analyze_user(user_id, input_data)
            
        except Exception as e:
            logger.error(f"Error analyzing insider threat: {e}")
            return None
    
    def _analyze_user(self, user_id: str, current_activity: Dict) -> Optional[SecurityEvent]:
        """Analyze a user's activity"""
        indicators = []
        score = 0.0
        confidence = 0.3
        
        # Get user's history
        history = self.user_activity[user_id]
        if len(history) < 10:
            # Not enough data for baseline
            return None
        
        # 1. Check after-hours access
        timestamp = datetime.fromisoformat(current_activity.get("timestamp", datetime.now().isoformat()))
        if self._is_after_hours(timestamp):
            indicators.append("after_hours_access")
            score += 0.3
            confidence = max(confidence, 0.4)
        
        # 2. Check weekend access
        if self._is_weekend(timestamp):
            indicators.append("weekend_access")
            score += 0.2
            confidence = max(confidence, 0.3)
        
        # 3. Check large data transfer
        if current_activity.get("data_size", 0) > self.config["large_download_threshold"]:
            indicators.append("large_data_transfer")
            score += 0.4
            confidence = max(confidence, 0.6)
        
        # 4. Check high frequency
        recent = [a for a in history 
                 if (datetime.now() - datetime.fromisoformat(a.get("timestamp", datetime.now().isoformat()))).total_seconds() < 3600]
        if len(recent) > self.config["high_frequency_threshold"]:
            indicators.append("high_request_frequency")
            score += 0.3
            confidence = max(confidence, 0.5)
        
        # 5. Check unusual data access
        if "unusual_access" in current_activity.get("flags", []):
            indicators.append("unusual_data_access")
            score += 0.5
            confidence = max(confidence, 0.7)
        
        # 6. Check for privilege escalation attempts
        if current_activity.get("privilege_escalation", False):
            indicators.append("privilege_escalation_attempt")
            score += 0.6
            confidence = max(confidence, 0.8)
        
        # 7. Check for data exfiltration patterns
        if current_activity.get("external_transfer", False):
            indicators.append("external_data_transfer")
            score += 0.5
            confidence = max(confidence, 0.7)
        
        # Normalize
        score = min(score, 1.0)
        confidence = min(confidence, 0.95)
        
        if score > 0.5:
            severity = "HIGH" if score > 0.8 else "MEDIUM"
            return self.generate_event(
                event_type="insider_threat_detected",
                severity=severity,
                description=f"Potential insider threat detected for user {user_id}",
                data={
                    "user_id": user_id,
                    "score": score,
                    "confidence": confidence,
                    "indicators": indicators,
                    "activity": current_activity
                },
                confidence=confidence
            )
        
        return None
    
    def _is_after_hours(self, timestamp: datetime) -> bool:
        """Check if timestamp is after hours"""
        hour = timestamp.hour
        start = self.config["after_hours_start"]
        end = self.config["after_hours_end"]
        return hour >= start or hour < end
    
    def _is_weekend(self, timestamp: datetime) -> bool:
        """Check if timestamp is on a weekend"""
        return timestamp.weekday() in self.config["weekend_days"]