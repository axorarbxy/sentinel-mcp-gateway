"""
Insider Threat Detection Module
Flags anomalous behavior from internal users
"""

from typing import Dict, Any, Optional, List
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import logging
from ..base_module import SecurityModule, SecurityEvent

logger = logging.getLogger(__name__)

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
            
            activity = dict(input_data)
            activity["timestamp"] = self._parse_timestamp(input_data.get("timestamp")).isoformat()

            # Score every submitted event; demo and first-seen user activity
            # should not disappear while a ten-event baseline is collected.
            self.user_activity[user_id].append(activity)
            
            # Keep only recent activity
            cutoff = datetime.now(timezone.utc) - timedelta(days=30)
            self.user_activity[user_id] = [
                a for a in self.user_activity[user_id]
                if self._parse_timestamp(a.get("timestamp")) > cutoff
            ]
            
            # Analyze for anomalies
            return self._analyze_user(user_id, activity)
            
        except Exception as e:
            logger.error(f"Error analyzing insider threat: {e}")
            return None
    
    def _analyze_user(self, user_id: str, current_activity: Dict) -> Optional[SecurityEvent]:
        """Analyze a user's activity"""
        indicators = []
        score = 0.0
        confidence = 0.45
        
        # Get user's history
        history = self.user_activity[user_id]
        # Behavioral baselines improve over time, but deterministic indicators
        # can score a single event without waiting for history.
        
        # 1. Check after-hours access
        timestamp = self._parse_timestamp(current_activity.get("timestamp"))
        try:
            activity_hour = int(current_activity.get("local_hour", timestamp.hour))
        except (TypeError, ValueError):
            activity_hour = timestamp.hour
        try:
            activity_weekday = int(current_activity.get("local_weekday", timestamp.weekday()))
        except (TypeError, ValueError):
            activity_weekday = timestamp.weekday()
        if self._is_after_hours(timestamp.replace(hour=activity_hour % 24)):
            indicators.append("after_hours_access")
            score += 0.15
            confidence = max(confidence, 0.5)
        
        # 2. Check weekend access
        if activity_weekday in self.config["weekend_days"]:
            indicators.append("weekend_access")
            score += 0.15
            confidence = max(confidence, 0.5)
        
        # 3. Check large data transfer
        try:
            data_size = float(current_activity.get("data_size", 0))
        except (TypeError, ValueError):
            data_size = 0
        if data_size > self.config["large_download_threshold"]:
            indicators.append("large_data_transfer")
            score += 0.4
            confidence = max(confidence, 0.6)

        try:
            record_count = int(current_activity.get("records_count", current_activity.get("record_count", 0)))
        except (TypeError, ValueError):
            record_count = 0
        if record_count >= 1000:
            indicators.append("bulk_record_access")
            score += 0.4
            confidence = max(confidence, 0.75)
        elif record_count >= 250:
            indicators.append("large_record_access")
            score += 0.25
            confidence = max(confidence, 0.65)

        activity_text = " ".join(str(current_activity.get(key, "")) for key in ("action", "result", "description")).lower()
        if any(term in activity_text for term in ("bulk export", "mass export", "bulk download", "database dump")):
            indicators.append("bulk_export_activity")
            score += 0.4
            confidence = max(confidence, 0.75)
        elif any(term in activity_text for term in ("download", "export")):
            indicators.append("data_download_or_export")
            score += 0.2
            confidence = max(confidence, 0.6)

        location_text = str(current_activity.get("location", "")).lower()
        if (current_activity.get("unfamiliar_location") or current_activity.get("unfamiliar_ip")
                or "unfamiliar" in location_text or "unknown" in location_text):
            indicators.append("unfamiliar_location_or_ip")
            score += 0.3
            confidence = max(confidence, 0.7)
        
        # 4. Check high frequency
        now = datetime.now(timezone.utc)
        recent = [a for a in history
                  if (now - self._parse_timestamp(a.get("timestamp"))).total_seconds() < 3600]
        if len(recent) > self.config["high_frequency_threshold"]:
            indicators.append("high_request_frequency")
            score += 0.3
            confidence = max(confidence, 0.5)
        
        # 5. Check unusual data access
        flags = current_activity.get("flags", [])
        if not isinstance(flags, (list, tuple, set)):
            flags = [str(flags)]
        normalized_flags = {str(flag).lower() for flag in flags}
        if "unusual_access" in normalized_flags or "suspicious_activity" in normalized_flags:
            indicators.append("unusual_data_access")
            score += 0.5
            confidence = max(confidence, 0.7)
        
        # 6. Check for privilege escalation attempts
        if current_activity.get("privilege_escalation", False):
            indicators.append("privilege_escalation_attempt")
            score += 0.6
            confidence = max(confidence, 0.8)
        
        # 7. Check for data exfiltration patterns
        if current_activity.get("external_transfer", False) or any(term in activity_text for term in ("external transfer", "uploaded externally", "sent to external")):
            indicators.append("external_data_transfer")
            score += 0.5
            confidence = max(confidence, 0.7)
        
        # Normalize
        confidence = min(confidence, 0.95)
        
        score = min(score, 1.0)
        if score >= 0.5:
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

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        try:
            parsed = datetime.fromisoformat(str(value)) if value else datetime.now(timezone.utc)
        except (TypeError, ValueError):
            parsed = datetime.now(timezone.utc)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    
    def _is_after_hours(self, timestamp: datetime) -> bool:
        """Check if timestamp is after hours"""
        hour = timestamp.hour
        start = self.config["after_hours_start"]
        end = self.config["after_hours_end"]
        return hour >= start or hour < end
    
    def _is_weekend(self, timestamp: datetime) -> bool:
        """Check if timestamp is on a weekend"""
        return timestamp.weekday() in self.config["weekend_days"]
