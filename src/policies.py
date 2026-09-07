"""
Sentinel-MCP Policy Engine
Implements security policies based on 2026 SECUREVENT research
"""

import re
import logging
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class PolicyAction(Enum):
    """Action to take when a policy is violated"""
    ALLOW = "allow"
    BLOCK = "block"
    ALERT = "alert"
    LOG = "log"

@dataclass
class PolicyResult:
    """Result of policy evaluation"""
    allowed: bool
    action: PolicyAction
    reason: str
    details: Dict[str, Any]

class SecurityPolicy:
    """Security policy definitions"""
    
    # Blocked paths - sensitive system files
    BLOCKED_PATHS = [
        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/hosts",
        r"/proc/.*",
        r"/sys/.*",
        r"/var/log/.*",
        r"/root/.*",
        r"\.env$",
        r"\.git/.*",
        r"config\.json$",
        r"secret\.*",
        r"credentials\.*",
        r"\.pem$",
        r"\.key$",
        r"\.cert$"
    ]
    
    # Allowed commands (whitelist)
    ALLOWED_COMMANDS = [
        r"^ls$",
        r"^pwd$",
        r"^echo$",
        r"^cat (?!.*/etc/.*|.*/root/.*).*$",  # cat allowed but not for sensitive paths
        r"^whoami$",
        r"^date$",
        r"^uptime$",
        r"^ps$"
    ]
    
    # Dangerous SQL patterns
    DANGEROUS_SQL = [
        r"DROP\s+TABLE",
        r"DELETE\s+FROM",
        r"TRUNCATE\s+TABLE",
        r"ALTER\s+TABLE",
        r"CREATE\s+USER",
        r"GRANT\s+ALL",
        r"INSERT\s+INTO.*\..*\.\..*"  # Insert into system tables
    ]

class PolicyEngine:
    """Evaluates MCP requests against security policies"""
    
    def __init__(self):
        self.policies = []
        self.blocked_paths = SecurityPolicy.BLOCKED_PATHS
        self.allowed_commands = SecurityPolicy.ALLOWED_COMMANDS
        self.dangerous_sql = SecurityPolicy.DANGEROUS_SQL
        logger.info("🔒 Policy Engine initialized")
    
    def evaluate(self, method: str, params: Dict) -> PolicyResult:
        """Evaluate an MCP request against all policies"""
        
        # Default: block by default (zero-trust)
        result = PolicyResult(
            allowed=False,
            action=PolicyAction.BLOCK,
            reason="Default deny",
            details={"method": method}
        )
        
        # Route to appropriate policy handler
        if method.startswith("filesystem/"):
            result = self._evaluate_filesystem(method, params)
        elif method.startswith("shell/") or method.startswith("execute"):
            result = self._evaluate_shell(method, params)
        elif method.startswith("db/") or method.startswith("sql/"):
            result = self._evaluate_database(method, params)
        elif method.startswith("network/"):
            result = self._evaluate_network(method, params)
        else:
            # Unknown method - block with warning
            result = PolicyResult(
                allowed=False,
                action=PolicyAction.BLOCK,
                reason=f"Unknown method: {method} - not in allowed list",
                details={"method": method, "params": params}
            )
        
        # Log the decision
        logger.info(f"📋 Policy result for {method}: {result.action.value} - {result.reason}")
        return result
    
    def _evaluate_filesystem(self, method: str, params: Dict) -> PolicyResult:
        """Evaluate filesystem operations"""
        
        # Extract path from params
        path = params.get("path") or params.get("file") or params.get("directory", "")
        
        # Check for sensitive paths
        for blocked_pattern in self.blocked_paths:
            if re.search(blocked_pattern, path, re.IGNORECASE):
                return PolicyResult(
                    allowed=False,
                    action=PolicyAction.BLOCK,
                    reason=f"Access denied: {path} matches blocked pattern {blocked_pattern}",
                    details={"path": path, "blocked_pattern": blocked_pattern}
                )
        
        # Check for path traversal attempts
        if ".." in path:
            return PolicyResult(
                allowed=False,
                action=PolicyAction.BLOCK,
                reason=f"Path traversal attempt detected: {path}",
                details={"path": path}
            )
        
        # Write operations need extra scrutiny
        if method in ["filesystem/write", "filesystem/delete", "filesystem/mkdir"]:
            # Check if writing to allowed directories
            if not any(allowed_dir in path for allowed_dir in ["/tmp", "/home/user", "/data"]):
                return PolicyResult(
                    allowed=False,
                    action=PolicyAction.BLOCK,
                    reason=f"Write operation not allowed in {path}",
                    details={"path": path, "method": method}
                )
        
        return PolicyResult(
            allowed=True,
            action=PolicyAction.ALLOW,
            reason="Filesystem access allowed",
            details={"path": path}
        )
    
    def _evaluate_shell(self, method: str, params: Dict) -> PolicyResult:
        """Evaluate shell command execution"""
        
        command = params.get("command") or params.get("cmd", "")
        
        # Check against allowed commands
        for allowed_pattern in self.allowed_commands:
            if re.match(allowed_pattern, command, re.IGNORECASE):
                return PolicyResult(
                    allowed=True,
                    action=PolicyAction.ALLOW,
                    reason="Command allowed by whitelist",
                    details={"command": command}
                )
        
        # Block unknown commands
        return PolicyResult(
            allowed=False,
            action=PolicyAction.BLOCK,
            reason=f"Command {command} not in allowed whitelist",
            details={"command": command}
        )
    
    def _evaluate_database(self, method: str, params: Dict) -> PolicyResult:
        """Evaluate database operations"""
        
        sql = params.get("sql") or params.get("query", "")
        
        # Check for dangerous SQL patterns
        for dangerous_pattern in self.dangerous_sql:
            if re.search(dangerous_pattern, sql, re.IGNORECASE):
                return PolicyResult(
                    allowed=False,
                    action=PolicyAction.BLOCK,
                    reason=f"Dangerous SQL pattern detected: {dangerous_pattern}",
                    details={"sql": sql, "pattern": dangerous_pattern}
                )
        
        # Read-only operations are allowed
        if method in ["db/query", "db/select"]:
            return PolicyResult(
                allowed=True,
                action=PolicyAction.ALLOW,
                reason="Read-only database query allowed",
                details={"sql": sql}
            )
        
        # Write operations need scrutiny
        if method in ["db/insert", "db/update", "db/delete"]:
            # Check if targeting allowed tables
            allowed_tables = ["users", "products", "orders"]
            if any(table in sql.lower() for table in allowed_tables):
                return PolicyResult(
                    allowed=True,
                    action=PolicyAction.ALLOW,
                    reason="Database write to allowed table",
                    details={"sql": sql}
                )
            else:
                return PolicyResult(
                    allowed=False,
                    action=PolicyAction.BLOCK,
                    reason="Database write to unknown table",
                    details={"sql": sql}
                )
        
        return PolicyResult(
            allowed=False,
            action=PolicyAction.BLOCK,
            reason=f"Database operation {method} not allowed",
            details={"method": method}
        )
    
    def _evaluate_network(self, method: str, params: Dict) -> PolicyResult:
        """Evaluate network operations"""
        
        url = params.get("url") or params.get("host", "")
        
        # Block internal networks
        internal_patterns = [
            r"localhost",
            r"127\.0\.0\.\d+",
            r"192\.168\.\d+\.\d+",
            r"10\.\d+\.\d+\.\d+",
            r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+",
            r"\.internal\."
        ]
        
        for pattern in internal_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return PolicyResult(
                    allowed=False,
                    action=PolicyAction.BLOCK,
                    reason=f"Internal network access blocked: {url}",
                    details={"url": url, "pattern": pattern}
                )
        
        return PolicyResult(
            allowed=True,
            action=PolicyAction.ALLOW,
            reason="Network access allowed",
            details={"url": url}
        )