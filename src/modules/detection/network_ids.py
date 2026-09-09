"""
Network Intrusion Detection Module
Monitors network traffic for suspicious patterns
"""

import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from collections import defaultdict
from ..base_module import SecurityModule, SecurityEvent

class NetworkIDS(SecurityModule):
    """Detects network intrusions using pattern matching and heuristics"""
    
    def __init__(self):
        super().__init__("NetworkIDS", "detection")
        
        # Known attack signatures (simplified)
        self.attack_patterns = {
            "sql_injection": r'(union|select|insert|update|delete|drop).*from',
            "xss": r'<script.*>.*</script>',
            "command_injection": r'(\||;|&|\$\().*(ls|cat|echo|id|whoami)',
            "path_traversal": r'\.\./.*\.\./',
            "port_scan": r'(SYN|FIN|XMAS|NULL)',
            "ddos_pattern": r'(GET|POST|HEAD).*(/|\.html)',
        }
        
        # Suspicious ports
        self.suspicious_ports = {
            22: "SSH_bruteforce",
            23: "Telnet",
            445: "SMB_exploit",
            3306: "MySQL_scan",
            3389: "RDP_scan",
            5432: "PostgreSQL_scan",
            6379: "Redis_scan",
            27017: "MongoDB_scan",
            8080: "Proxy_scan",
            8443: "HTTPS_alt_scan"
        }
        
        # Traffic tracking
        self.ip_connections = defaultdict(list)
        self.ip_requests = defaultdict(int)
        self.connection_threshold = 100  # Connections per minute
        
        self.config = {
            "connection_threshold": 100,
            "time_window": 60,  # seconds
            "check_attack_patterns": True,
            "check_suspicious_ports": True,
            "check_rate_limiting": True
        }
    
    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "input_types": ["network_flow", "packet_data", "connection_log"],
            "detection_methods": [
                "attack_signature_matching",
                "port_anomaly_detection",
                "rate_limiting_analysis",
                "protocol_anomaly_detection"
            ],
            "output": "intrusion_score + attack_type"
        }
    
    def analyze(self, input_data: Any) -> Optional[SecurityEvent]:
        """Analyze network traffic for intrusions"""
        try:
            if isinstance(input_data, dict):
                return self._analyze_network_data(input_data)
            elif isinstance(input_data, str):
                return self._analyze_log_entry(input_data)
            else:
                return None
        except Exception as e:
            logger.error(f"Error analyzing network data: {e}")
            return None
    
    def _analyze_network_data(self, data: Dict) -> Optional[SecurityEvent]:
        """Analyze structured network data"""
        indicators = []
        score = 0.0
        confidence = 0.3
        
        # Extract data
        src_ip = data.get("src_ip", "")
        dst_ip = data.get("dst_ip", "")
        src_port = data.get("src_port", 0)
        dst_port = data.get("dst_port", 0)
        protocol = data.get("protocol", "").upper()
        payload = data.get("payload", "")
        
        # 1. Check attack patterns in payload
        for attack_name, pattern in self.attack_patterns.items():
            if re.search(pattern, str(payload).lower(), re.IGNORECASE):
                indicators.append(f"attack_{attack_name}")
                score += 0.6
                confidence = max(confidence, 0.8)
                
                # Alert immediately for critical attacks
                if attack_name in ["command_injection", "sql_injection"]:
                    return self.generate_event(
                        event_type=f"attack_detected_{attack_name}",
                        severity="CRITICAL",
                        description=f"{attack_name.upper()} attack detected from {src_ip}",
                        data={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "attack_type": attack_name,
                            "payload": payload[:200]
                        },
                        confidence=0.9
                    )
        
        # 2. Check suspicious ports
        if dst_port in self.suspicious_ports:
            indicators.append(f"suspicious_port_{dst_port}")
            score += 0.3
            confidence = max(confidence, 0.5)
        
        # 3. Check for port scans (many connections to different ports)
        if src_ip:
            self.ip_connections[src_ip].append(datetime.now())
            current_time = datetime.now()
            recent = [t for t in self.ip_connections[src_ip] 
                     if (current_time - t).total_seconds() < self.config["time_window"]]
            self.ip_connections[src_ip] = recent
            
            if len(recent) > self.config["connection_threshold"]:
                indicators.append("port_scan_detected")
                score += 0.7
                confidence = max(confidence, 0.85)
        
        # 4. Check for unusual protocols on standard ports
        if dst_port == 80 and protocol not in ["HTTP", "TCP"]:
            indicators.append("protocol_mismatch_http")
            score += 0.2
            confidence = max(confidence, 0.4)
        
        # Normalize
        score = min(score, 1.0)
        confidence = min(confidence, 0.95)
        
        if score > 0.5:
            severity = "HIGH" if score > 0.8 else "MEDIUM"
            return self.generate_event(
                event_type="suspicious_traffic_detected",
                severity=severity,
                description=f"Suspicious network traffic detected from {src_ip or 'unknown'}",
                data={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "score": score,
                    "confidence": confidence,
                    "indicators": indicators
                },
                confidence=confidence
            )
        
        return None
    
    def _analyze_log_entry(self, log: str) -> Optional[SecurityEvent]:
        """Analyze a log entry string"""
        # Simple log parsing
        indicators = []
        score = 0.0
        
        # Check for common log patterns
        if "failed login" in log.lower():
            score += 0.3
            indicators.append("failed_login")
        
        if "password" in log.lower() or "credential" in log.lower():
            score += 0.2
            indicators.append("credential_mention")
        
        if "error" in log.lower():
            score += 0.1
        
        if score > 0.4:
            return self.generate_event(
                event_type="suspicious_log_entry",
                severity="LOW",
                description=f"Suspicious log entry detected",
                data={"log": log[:200], "indicators": indicators},
                confidence=0.5
            )
        
        return None