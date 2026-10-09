"""
Sentinel-MCP Behavioral Monitor
Implements anomaly detection based on SECUREVENT 2026 research
Tracks agent behavior patterns and detects deviations
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import deque, defaultdict
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import threading
import time

logger = logging.getLogger(__name__)

class BehavioralMonitor:
    """
    Monitors agent behavior and detects anomalies using Isolation Forest
    Based on SECUREVENT: "hybrid AI/ML security monitoring for distributed event-based systems"
    """
    
    def __init__(self, window_size: int = 100, contamination: float = 0.1):
        """
        Initialize the behavioral monitor
        
        Args:
            window_size: Number of requests to keep in history
            contamination: Expected proportion of outliers (anomalies)
        """
        self.window_size = window_size
        self.contamination = contamination
        
        # Store request history for each agent/session
        self.history = defaultdict(lambda: deque(maxlen=window_size))
        
        # Feature vectors for ML
        self.feature_history = defaultdict(lambda: deque(maxlen=window_size))
        
        # ML models per agent
        self.models = {}
        self.scalers = {}
        
        # Anomaly alerts
        self.alerts = []
        
        # Statistics
        self.total_requests = 0
        self.anomalies_detected = 0
        
        logger.info("🧠 Behavioral Monitor initialized with Isolation Forest")
    
    def extract_features(self, request: Dict) -> np.ndarray:
        """
        Extract features from a request for ML analysis
        
        Features based on SECUREVENT approach:
        - Request frequency (time since last request)
        - Method type (categorical encoded)
        - Parameter complexity (number of params)
        - Command length (if shell)
        - Path depth (if filesystem)
        - SQL complexity (if database)
        - Time of day (hour)
        """
        features = []
        
        # 1. Request timestamp features
        timestamp = datetime.fromisoformat(request.get("timestamp", datetime.now().isoformat()))
        features.append(timestamp.hour / 24.0)  # Hour of day (normalized)
        features.append(timestamp.weekday() / 7.0)  # Day of week (normalized)
        
        # 2. Method type encoding
        method = request.get("method", "")
        method_types = [
            "filesystem/read", "filesystem/write", "filesystem/delete",
            "shell/execute", "shell/command",
            "db/query", "db/insert", "db/update", "db/delete",
            "network/request", "network/get", "network/post"
        ]
        for mt in method_types:
            features.append(1.0 if method.startswith(mt) else 0.0)
        
        # 3. Parameter features
        params = request.get("params", {})
        features.append(len(params))  # Number of parameters
        
        # 4. Path features
        if "path" in params:
            path = params["path"]
            features.append(len(path.split("/")))  # Path depth
            features.append(1.0 if ".." in path else 0.0)  # Path traversal attempt
        else:
            features.append(0.0)
            features.append(0.0)
        
        # 5. Command features
        if "command" in params:
            cmd = params["command"]
            features.append(len(cmd.split()))  # Command complexity
            features.append(len(cmd))  # Command length
        else:
            features.append(0.0)
            features.append(0.0)
        
        # 6. SQL features
        if "sql" in params:
            sql = params["sql"]
            features.append(len(sql.split()))  # SQL complexity
            features.append(1.0 if any(word in sql.upper() for word in ["DROP", "DELETE", "INSERT"]) else 0.0)
        else:
            features.append(0.0)
            features.append(0.0)
        
        # 7. Frequency feature - time since last request
        # This is added separately during training
            
        return np.array(features)
    
    def get_frequency_feature(self, agent_id: str) -> float:
        """Calculate time since last request for this agent"""
        if agent_id in self.history and len(self.history[agent_id]) > 0:
            last_request = self.history[agent_id][-1]
            last_time = datetime.fromisoformat(last_request.get("timestamp", datetime.now().isoformat()))
            time_diff = (datetime.now() - last_time).total_seconds()
            # Normalize to [0, 1] with cap at 1 hour
            return min(time_diff / 3600.0, 1.0)
        return 1.0  # No history, assume normal
    
    def add_request(self, agent_id: str, request: Dict):
        """
        Add a request to the history and check for anomalies
        """
        self.total_requests += 1
        
        # Add timestamp if not present
        if "timestamp" not in request:
            request["timestamp"] = datetime.now().isoformat()
        
        # Store in history
        self.history[agent_id].append(request)
        
        # Extract features
        features = self.extract_features(request)
        
        # Add frequency feature
        freq_feature = self.get_frequency_feature(agent_id)
        features = np.append(features, freq_feature)
        
        # Store features
        self.feature_history[agent_id].append(features)
        
        # Detect anomalies if we have enough data
        if len(self.feature_history[agent_id]) >= 20:
            is_anomaly = self.detect_anomaly(agent_id, features)
            if is_anomaly:
                self.anomalies_detected += 1
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "agent_id": agent_id,
                    "request": request,
                    "type": "behavioral_anomaly",
                    "score": float(self.models[agent_id].score_samples([features])[0]) if agent_id in self.models else None
                }
                self.alerts.append(alert)
                logger.warning(f"🚨 ANOMALY DETECTED for agent {agent_id}: {request.get('method')}")
                return True, alert
        
        # Train model periodically
        if len(self.feature_history[agent_id]) >= 20 and agent_id not in self.models:
            self.train_model(agent_id)
        
        return False, None
    
    def train_model(self, agent_id: str):
        """
        Train Isolation Forest model for an agent
        """
        if agent_id not in self.feature_history:
            return
        
        X = np.array(list(self.feature_history[agent_id]))
        
        if len(X) < 20:
            return
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        self.scalers[agent_id] = scaler
        
        # Train Isolation Forest
        model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        model.fit(X_scaled)
        self.models[agent_id] = model
        
        logger.info(f"🧠 Trained model for agent {agent_id} on {len(X)} samples")
    
    def detect_anomaly(self, agent_id: str, features: np.ndarray) -> bool:
        """
        Detect if the current request is anomalous
        """
        if agent_id not in self.models:
            return False
        
        model = self.models[agent_id]
        scaler = self.scalers[agent_id]
        
        # Scale features
        features_scaled = scaler.transform([features])
        
        # Predict (-1 = anomaly, 1 = normal)
        prediction = model.predict(features_scaled)
        
        return prediction[0] == -1
    
    def get_agent_stats(self, agent_id: str) -> Dict:
        """Get statistics for a specific agent"""
        if agent_id not in self.history:
            return {"error": "Agent not found"}
        
        history = list(self.history[agent_id])
        methods = defaultdict(int)
        for req in history:
            methods[req.get("method", "unknown")] += 1
        
        return {
            "agent_id": agent_id,
            "request_count": len(history),
            "method_distribution": dict(methods),
            "is_monitored": agent_id in self.models,
            "anomaly_count": sum(1 for a in self.alerts if a.get("agent_id") == agent_id),
            "last_request": history[-1]["timestamp"] if history else None
        }
    
    def get_stats(self) -> Dict:
        """Get overall monitor statistics"""
        return {
            "total_requests": self.total_requests,
            "anomalies_detected": self.anomalies_detected,
            "agents_monitored": len(self.models),
            "total_alerts": len(self.alerts),
            "recent_alerts": self.alerts[-10:] if self.alerts else []
        }

class RequestAnalyzer:
    """
    Real-time request analyzer based on SECUREVENT hybrid approach
    Combines rule-based and ML-based detection
    """
    
    def __init__(self):
        self.suspicious_patterns = [
            # Rapid fire requests (DoS attempt)
            "rapid_request",
            # Unusual time patterns
            "unusual_hour",
            # Request chaining (related operations)
            "suspicious_chain"
        ]
        self.request_timestamps = defaultdict(list)
        self.chain_detector = defaultdict(list)
    
    def analyze(self, agent_id: str, request: Dict) -> Dict:
        """
        Analyze a request for rule-based anomalies
        Returns: {"anomaly": bool, "reason": str, "severity": str}
        """
        timestamp = datetime.fromisoformat(request.get("timestamp", datetime.now().isoformat()))
        
        # Check 1: Rapid request (10+ requests in 5 seconds)
        self.request_timestamps[agent_id].append(timestamp)
        recent = [t for t in self.request_timestamps[agent_id] if (timestamp - t).total_seconds() < 5]
        self.request_timestamps[agent_id] = [t for t in self.request_timestamps[agent_id] if (timestamp - t).total_seconds() < 60]
        
        if len(recent) > 10:
            return {
                "anomaly": True,
                "reason": "Rapid request burst detected",
                "severity": "HIGH",
                "details": f"{len(recent)} requests in 5 seconds"
            }
        
        # Check 2: Unusual hour (2 AM - 5 AM)
        if 2 <= timestamp.hour <= 5:
            # Check if this agent normally works during these hours
            if agent_id in self.request_timestamps:
                normal_hours = [t.hour for t in self.request_timestamps[agent_id] if (timestamp - t).total_seconds() < 3600*24*7]
                if len(normal_hours) > 10 and all(8 <= h <= 20 for h in normal_hours):
                    return {
                        "anomaly": True,
                        "reason": "Unusual work hours",
                        "severity": "MEDIUM",
                        "details": f"Request at {timestamp.hour}:00 when normally works 8-20"
                    }
        
        # Check 3: Suspicious operation chain
        # Example: read sensitive file -> shell execute -> network exfil
        method = request.get("method", "")
        if "filesystem/read" in method or "shell/execute" in method:
            self.chain_detector[agent_id].append({
                "method": method,
                "timestamp": timestamp
            })
            self.chain_detector[agent_id] = [c for c in self.chain_detector[agent_id] 
                                            if (timestamp - c["timestamp"]).total_seconds() < 10]
            
            if len(self.chain_detector[agent_id]) > 3:
                chain_methods = [c["method"] for c in self.chain_detector[agent_id]]
                if "filesystem/read" in chain_methods and "shell/execute" in chain_methods:
                    return {
                        "anomaly": True,
                        "reason": "Suspicious operation chain: read → execute",
                        "severity": "HIGH",
                        "details": f"Chain: {', '.join(chain_methods)}"
                    }
        
        return {"anomaly": False, "reason": "Normal", "severity": "LOW"}