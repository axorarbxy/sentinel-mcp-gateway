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
        # Only successful requests teach the baseline; rejected traffic cannot
        # make malicious behavior look normal.
        self.allowed_tool_counts = defaultdict(lambda: defaultdict(int))
        
        # ML models per agent
        self.models = {}
        self.scalers = {}
        self.model_sample_counts = {}
        self.total_allowed_samples = defaultdict(int)
        
        # Anomaly alerts
        self.alerts = []
        
        # Statistics
        self.total_requests = 0
        self.anomalies_detected = 0
        self.learning_quarantined = 0
        
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
        method = request.get("method", "")

        # 2. MCP method type encoding
        mcp_methods = (
            "tools/call", "tools/list", "resources/read", "resources/list",
            "prompts/get", "prompts/list", "initialize", "notifications/initialized",
        )
        for mcp_method in mcp_methods:
            features.append(1.0 if method == mcp_method else 0.0)

        # 3. Method type encoding for non-MCP-specific integrations
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
        # Aggregate shape only: do not put raw arguments into the model history.
        features.append(min(float(request.get("argument_bytes", 0)) / 65536.0, 1.0))
        features.append(min(float(request.get("argument_depth", 0)) / 32.0, 1.0))
        features.append(min(float(request.get("argument_keys", 0)) / 128.0, 1.0))
        features.append(min(float(request.get("argument_string_bytes", 0)) / 32768.0, 1.0))
        
        # 4. Path features
        if "path" in params:
            path = str(params["path"])
            features.append(len(path.split("/")))  # Path depth
            features.append(1.0 if ".." in path else 0.0)  # Path traversal attempt
        else:
            features.append(0.0)
            features.append(0.0)
        
        # 5. Command features
        if "command" in params:
            cmd = str(params["command"])
            features.append(len(cmd.split()))  # Command complexity
            features.append(len(cmd))  # Command length
        else:
            features.append(0.0)
            features.append(0.0)
        
        # 6. SQL features
        if "sql" in params:
            sql = str(params["sql"])
            features.append(len(sql.split()))  # SQL complexity
            features.append(1.0 if any(word in sql.upper() for word in ["DROP", "DELETE", "INSERT"]) else 0.0)
        else:
            features.append(0.0)
            features.append(0.0)
        
        # 7. Frequency feature - time since last request
        # This is added separately during training
            
        return np.array(features)

    @staticmethod
    def feature_names() -> List[str]:
        """Names aligned with extract_features and the two appended context features."""
        return [
            "hour_of_day", "day_of_week",
            *[f"method:{name}" for name in (
                "tools/call", "tools/list", "resources/read", "resources/list",
                "prompts/get", "prompts/list", "initialize", "notifications/initialized",
            )],
            *[f"operation:{name}" for name in (
                "filesystem/read", "filesystem/write", "filesystem/delete",
                "shell/execute", "shell/command", "db/query", "db/insert",
                "db/update", "db/delete", "network/request", "network/get", "network/post",
            )],
            "parameter_count", "argument_bytes", "argument_depth", "argument_keys",
            "argument_string_bytes", "path_depth", "path_traversal", "command_words",
            "command_length", "sql_words", "sql_mutation_keyword", "new_tool",
            "prior_tool_use_rate", "seconds_since_previous_request",
        ]

    def explain_anomaly(self, agent_id: str, features: np.ndarray, limit: int = 4) -> List[Dict[str, Any]]:
        """Report baseline deviations as evidence; these are not model feature importances."""
        scaler = self.scalers.get(agent_id)
        if scaler is None:
            return []
        scaled = scaler.transform([features])[0]
        names = self.feature_names()
        ranked = sorted(enumerate(np.abs(scaled)), key=lambda item: item[1], reverse=True)
        return [
            {"feature": names[index], "observed_z_score": round(float(scaled[index]), 3)}
            for index, magnitude in ranked[:limit]
            if magnitude >= 1.0
        ]
    
    def get_frequency_feature(self, agent_id: str) -> float:
        """Calculate time since last request for this agent"""
        if agent_id in self.history and len(self.history[agent_id]) > 0:
            last_request = self.history[agent_id][-1]
            last_time = datetime.fromisoformat(last_request.get("timestamp", datetime.now().isoformat()))
            now = datetime.now(last_time.tzinfo) if last_time.tzinfo else datetime.now()
            time_diff = (now - last_time).total_seconds()
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
        
        # Compare against the clean baseline before recording this observation.
        tool_name = str(request.get("tool_name") or "")
        prior_tool_uses = self.allowed_tool_counts[agent_id].get(tool_name, 0) if tool_name else 0
        features = self.extract_features(request)
        features = np.append(features, 1.0 if tool_name and prior_tool_uses == 0 else 0.0)
        features = np.append(features, min(np.log1p(prior_tool_uses) / 8.0, 1.0))
        
        # Add frequency feature
        freq_feature = self.get_frequency_feature(agent_id)
        features = np.append(features, freq_feature)
        
        # Store in history after computing the interval from the previous request.
        self.history[agent_id].append(request)

        decision = str(request.get("decision", "allow")).lower()
        anomaly_alert = None

        # Score against the last trained baseline. Learning is performed below,
        # after scoring, so a suspicious request cannot normalize itself.
        if agent_id in self.models:
            is_anomaly = self.detect_anomaly(agent_id, features)
            if is_anomaly:
                self.anomalies_detected += 1
                raw_score = float(self.models[agent_id].score_samples(
                    self.scalers[agent_id].transform([features])
                )[0])
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "agent_id": agent_id,
                    "request": {
                        "timestamp": request.get("timestamp"),
                        "method": request.get("method"),
                        "tool_name": request.get("tool_name"),
                    },
                    "type": "behavioral_anomaly",
                    "score": raw_score,
                    "score_type": "isolation_forest_raw_score",
                    "model_version": "behavioral-isolation-forest-v1",
                    "explanation": self.explain_anomaly(agent_id, features),
                    "learning_status": "quarantined",
                }
                self.alerts.append(alert)
                logger.warning(f"🚨 ANOMALY DETECTED for agent {agent_id}: {request.get('method')}")
                anomaly_alert = alert
        
        # Never let a model-flagged sample teach its own baseline. Deterministic
        # policy decisions remain authoritative; this only controls ML learning.
        if decision == "allow" and anomaly_alert is None:
            self.feature_history[agent_id].append(features)
            self.total_allowed_samples[agent_id] += 1
            if tool_name:
                self.allowed_tool_counts[agent_id][tool_name] += 1
        elif anomaly_alert is not None:
            self.learning_quarantined += 1

        # Refit from the bounded recent history to adapt to gradual workload
        # changes. The cumulative count still advances when the deque is full.
        refit_interval = max(5, min(20, self.window_size // 5))
        last_fit_count = self.model_sample_counts.get(agent_id, 0)
        if self.total_allowed_samples[agent_id] >= 20 and (
            agent_id not in self.models
            or self.total_allowed_samples[agent_id] - last_fit_count >= refit_interval
        ):
            self.train_model(agent_id)
        
        return anomaly_alert is not None, anomaly_alert
    
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
        self.model_sample_counts[agent_id] = self.total_allowed_samples[agent_id]
        
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
            "agents_with_baseline": len(self.feature_history),
            "training_samples": sum(len(samples) for samples in self.feature_history.values()),
            "learning_quarantined": self.learning_quarantined,
            "learning_policy": "allow-only; model anomalies quarantined from training",
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
