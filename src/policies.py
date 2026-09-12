"""
Sentinel-MCP Policy Engine
Enforces access control, path validation, and sanitization rules
on intercepted MCP tool calls.
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------- Result object returned by every policy check ----------
@dataclass
class PolicyResult:
    allowed: bool
    rule: str
    reason: str
    severity: str = "info"  # info | low | medium | high | critical
    metadata: Dict[str, Any] = field(default_factory=dict)


class PolicyAction(str, Enum):
    """The final action selected after evaluating all policy checks."""

    ALLOW = "allow"
    BLOCK = "block"


@dataclass
class PolicyDecision:
    """Aggregate result returned by :class:`PolicyEngine`.

    ``gateway.py`` needs one decision per request, while the individual policy
    functions intentionally return one result each.  Keeping both types makes
    the standalone checks usable and provides the gateway with a stable API.
    """

    allowed: bool
    reason: str
    details: List[Dict[str, Any]]
    action: PolicyAction


# ---------- Path Traversal Policy ----------
SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/root/",
    "C:\\Windows\\System32",
    "C:\\Users\\",
    "~/.ssh",
    ".env",
    "id_rsa",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",          # ../
    r"\.\.\\",         # ..\
    r"%2e%2e",         # URL-encoded ..
    r"\x00",           # null byte injection
]


def check_path_traversal(payload: Dict[str, Any]) -> PolicyResult:
    """
    Scans tool call arguments for sensitive paths or traversal attempts.
    """
    args = payload.get("params", {}).get("arguments", {}) or {}
    blob = str(args).lower()

    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, blob):
            return PolicyResult(
                allowed=False,
                rule="PATH_TRAVERSAL",
                reason=f"Traversal pattern detected: {pattern}",
                severity="high",
                metadata={"pattern": pattern, "args": args},
            )

    for sensitive in SENSITIVE_PATHS:
        if sensitive.lower() in blob:
            return PolicyResult(
                allowed=False,
                rule="SENSITIVE_PATH_ACCESS",
                reason=f"Attempt to access sensitive path: {sensitive}",
                severity="critical",
                metadata={"path": sensitive, "args": args},
            )

    return PolicyResult(
        allowed=True,
        rule="PATH_TRAVERSAL",
        reason="No traversal or sensitive path detected",
        severity="info",
    )


# ---------- ACL Policy ----------
# Maps tool name -> allowed argument constraints
DEFAULT_ACL = {
    "read_file": {"allow_read": True, "allow_write": False},
    "write_file": {"allow_read": False, "allow_write": True},
    "shell_exec": {"allow": False},   # blocked by default
    "list_dir": {"allow": True},
    # Legacy gateway clients send the tool as the JSON-RPC method rather than
    # as params.name. Support that form without classifying it as malformed.
    "filesystem/read": {"allow": True},
    "filesystem/write": {"allow": True},
    "filesystem/delete": {"allow": False},
    "shell/execute": {"allow": True},
    "db/query": {"allow": True},
    "network/request": {"allow": True},
}


def check_acl(payload: Dict[str, Any], acl: Optional[Dict] = None) -> PolicyResult:
    """
    Enforces tool-level access control.
    """
    acl = acl or DEFAULT_ACL
    tool = payload.get("params", {}).get("name")
    if not tool and payload.get("method") != "tools/call":
        tool = payload.get("method")
    if not tool:
        return PolicyResult(
            allowed=False,
            rule="ACL",
            reason="Missing tool name in request",
            severity="medium",
        )

    if tool not in acl:
        return PolicyResult(
            allowed=False,
            rule="ACL",
            reason=f"Tool '{tool}' is not in the allow-list",
            severity="high",
            metadata={"tool": tool},
        )

    rules = acl[tool]
    if rules.get("allow") is False:
        return PolicyResult(
            allowed=False,
            rule="ACL",
            reason=f"Tool '{tool}' is explicitly blocked",
            severity="critical",
            metadata={"tool": tool},
        )

    return PolicyResult(
        allowed=True,
        rule="ACL",
        reason=f"Tool '{tool}' permitted by ACL",
        severity="info",
        metadata={"tool": tool},
    )


# ---------- Composite Evaluation ----------
def evaluate(payload: Dict[str, Any], acl: Optional[Dict] = None) -> List[PolicyResult]:
    """
    Runs all policies and returns their results.
    The gateway will decide based on `allowed` fields.
    """
    return [
        check_acl(payload, acl),
        check_path_traversal(payload),
        check_shell_command(payload),
        check_sql_query(payload),
    ]


def _arguments(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Use MCP arguments, or the legacy method parameters when present."""
    params = payload.get("params", {}) or {}
    return params.get("arguments", params.get("args", params)) or {}


def check_shell_command(payload: Dict[str, Any]) -> PolicyResult:
    """Allow a deliberately small command set for legacy shell requests."""
    if payload.get("method") != "shell/execute":
        return PolicyResult(True, "SHELL_COMMAND", "Not a shell command")
    command = str(_arguments(payload).get("command", "")).strip()
    allowed_commands = {"ls", "pwd", "echo", "whoami", "date", "uptime", "ps", "cat"}
    command_name = command.split(maxsplit=1)[0] if command else ""
    if command_name not in allowed_commands:
        return PolicyResult(False, "SHELL_COMMAND", f"Command '{command_name or 'empty'}' is not allow-listed", "critical")
    return PolicyResult(True, "SHELL_COMMAND", "Command permitted by allow-list")


def check_sql_query(payload: Dict[str, Any]) -> PolicyResult:
    """Allow read-only legacy database queries and block destructive SQL."""
    if payload.get("method") != "db/query":
        return PolicyResult(True, "SQL_SAFETY", "Not a database query")
    query = str(_arguments(payload).get("sql", "")).strip()
    if not query.upper().startswith("SELECT"):
        return PolicyResult(False, "SQL_SAFETY", "Only read-only SELECT queries are permitted", "high")
    return PolicyResult(True, "SQL_SAFETY", "Read-only query permitted")


class PolicyEngine:
    """Evaluates gateway requests using the policy functions in this module."""

    def __init__(self, acl: Optional[Dict[str, Dict[str, Any]]] = None):
        self.acl = acl

    def evaluate(self, method: str, params: Optional[Dict[str, Any]] = None) -> PolicyDecision:
        """Return a single allow/block decision for a JSON-RPC request.

        MCP's ``tools/call`` parameters use ``name`` and ``arguments``.  The
        normalisation below also accepts ``args`` so callers using that common
        spelling are checked rather than silently bypassing path validation.
        """
        request_params = params or {}
        arguments = request_params.get("arguments", request_params.get("args", request_params))
        payload = {
            "method": method,
            "params": {
                **request_params,
                "arguments": arguments,
            },
        }
        results = evaluate(payload, self.acl)
        blocked = [result for result in results if not result.allowed]
        details = [
            {
                "rule": result.rule,
                "allowed": result.allowed,
                "reason": result.reason,
                "severity": result.severity,
                "metadata": result.metadata,
            }
            for result in results
        ]

        if blocked:
            return PolicyDecision(
                allowed=False,
                reason="; ".join(result.reason for result in blocked),
                details=details,
                action=PolicyAction.BLOCK,
            )

        return PolicyDecision(
            allowed=True,
            reason="All policy checks passed",
            details=details,
            action=PolicyAction.ALLOW,
        )
