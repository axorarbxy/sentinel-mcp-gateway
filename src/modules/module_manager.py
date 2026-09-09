"""
Module Manager - Orchestrates all CyberEye modules
"""

import logging
from typing import Dict, Any, List, Optional
from .base_module import SecurityModule, SecurityEvent
from .detection.phishing_detector import PhishingDetector
from .detection.malware_detector import MalwareDetector
from .detection.network_ids import NetworkIDS
from .detection.insider_threat import InsiderThreatDetector
from .detection.android_security import AndroidSecurityAnalyzer
from .utility.password_analyzer import PasswordAnalyzer
from .utility.qr_scanner import QRSafetyChecker

logger = logging.getLogger(__name__)

class ModuleManager:
    """Manages all security modules and coordinates analysis"""
    
    def __init__(self):
        self.modules: Dict[str, SecurityModule] = {}
        self.events: List[SecurityEvent] = []
        self._initialize_modules()
    
    def _initialize_modules(self):
        """Initialize all security modules"""
        # Detection modules
        self.register_module(PhishingDetector())
        self.register_module(MalwareDetector())
        self.register_module(NetworkIDS())
        self.register_module(InsiderThreatDetector())
        self.register_module(AndroidSecurityAnalyzer())
        
        # Utility modules
        self.register_module(PasswordAnalyzer())
        self.register_module(QRSafetyChecker())
        
        logger.info(f"✅ Initialized {len(self.modules)} CyberEye modules")
    
    def register_module(self, module: SecurityModule):
        """Register a module"""
        self.modules[module.name] = module
        logger.info(f"  - {module.name} ({module.module_type})")
    
    def analyze(self, input_type: str, input_data: Any) -> List[Dict]:
        """
        Route input to appropriate modules for analysis
        
        Args:
            input_type: Type of input (url, file, network, user, password, qr, android)
            input_data: The data to analyze
        
        Returns:
            List of security events
        """
        results = []
        
        # Map input types to relevant modules
        module_mapping = {
            "url": ["PhishingDetector"],
            "file": ["MalwareDetector"],
            "network": ["NetworkIDS"],
            "user": ["InsiderThreatDetector"],
            "android": ["AndroidSecurityAnalyzer"],
            "password": ["PasswordAnalyzer"],
            "qr": ["QRSafetyChecker"]
        }
        
        # Get modules for this input type
        module_names = module_mapping.get(input_type, [])
        
        # If no specific mapping, try all modules
        if not module_names:
            module_names = list(self.modules.keys())
        
        # Analyze with each relevant module
        for module_name in module_names:
            if module_name in self.modules:
                module = self.modules[module_name]
                if module.enabled:
                    try:
                        event = module.analyze(input_data)
                        if event:
                            results.append(event.to_dict())
                            self.events.append(event)
                    except Exception as e:
                        logger.error(f"Error in module {module_name}: {e}")
        
        return results
    
    def get_all_events(self, limit: int = 100) -> List[Dict]:
        """Get all events from all modules"""
        all_events = []
        for module in self.modules.values():
            all_events.extend(module.get_recent_events(limit))
        return all_events
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent high/critical severity alerts"""
        alerts = []
        for event in reversed(self.events):
            if event.severity in ["HIGH", "CRITICAL"]:
                alerts.append(event.to_dict())
                if len(alerts) >= limit:
                    break
        return alerts
    
    def get_module_stats(self) -> Dict[str, Any]:
        """Get statistics for all modules"""
        stats = {
            "total_modules": len(self.modules),
            "total_events": len(self.events),
            "modules": {}
        }
        
        for name, module in self.modules.items():
            stats["modules"][name] = module.get_stats()
        
        return stats
    
    def get_risk_score(self) -> float:
        """Calculate overall risk score based on recent events"""
        if not self.events:
            return 0.0
        
        # Weight recent events higher
        recent_events = self.events[-20:]
        score = 0.0
        
        severity_weights = {
            "LOW": 1,
            "MEDIUM": 3,
            "HIGH": 7,
            "CRITICAL": 10
        }
        
        total_weight = 0
        for event in recent_events:
            weight = severity_weights.get(event.severity, 1)
            score += weight * (event.confidence or 0.5)
            total_weight += 1
        
        if total_weight > 0:
            score = (score / total_weight) / 10  # Normalize to 0-1
            return min(score, 1.0)
        
        return 0.0