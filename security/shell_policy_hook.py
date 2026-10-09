"""
shell_policy_hook.py — CyberEye Task 05

Integrates the shell analysis engine with the MCP interception decision hook.

Install by importing this module and calling ``install()``, which replaces
``mcp_interception.decision_hook`` with the policy-aware version that:

  1. Runs the existing baseline checks (allowed_tools, method direction, etc.)
  2. Runs the shell analysis engine on any tools/call with shell-capable args.
  3. Returns a block/flag/allow decision with full rule IDs for event recording.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_interception import Decision, InterceptionEvent, default_decision_hook
from shell_analysis import ShellAction, analyse_tool_call

logger = logging.getLogger(__name__)


async def shell_policy_decision_hook(
    event: InterceptionEvent,
    agent: dict[str, Any],
) -> Decision:
    """Policy-aware decision hook.

    Extends ``default_decision_hook`` with shell command analysis.
    Plugs into ``mcp_interception.decision_hook``.
    """
    # Run baseline checks first
    base = await default_decision_hook(event, agent)
    if base.action == "block":
        return base

    # Only analyse tools/call
    if event.method != "tools/call":
        return base

    tool_name = event.tool_name
    arguments = event.arguments if isinstance(event.arguments, dict) else {}

    # Build per-agent config from agent record
    agent_config: dict[str, Any] = {
        "shell_mode": agent.get("shell_mode", "enforce"),
        "shell_profile": agent.get("shell_profile", "default"),
        "shell_allowlist": agent.get("shell_allowlist"),   # None = blocklist mode
        "workspace_roots": _parse_workspace_roots(agent.get("workspace_roots")),
    }

    try:
        shell_result = analyse_tool_call(tool_name, arguments, agent_config)
    except Exception:
        logger.exception(
            "Shell policy engine error event_id=%s tool=%s",
            event.event_id, tool_name,
        )
        return Decision(
            "block",
            "Shell policy engine failed; failing closed",
            ["SHELL-ENGINE-ERROR"],
        )

    if shell_result is None:
        # No shell content detected → pass through
        return base

    # Attach shell analysis metadata to event payload for observability
    _attach_shell_metadata(event, shell_result)

    action = shell_result.action
    rule_ids = list(shell_result.rule_ids)

    if action == ShellAction.BLOCK:
        # Block message is useful but does not reveal rule internals
        categories = list({f.category for f in shell_result.findings})
        reason = _safe_block_reason(categories, shell_result.findings)
        return Decision("block", reason, rule_ids)

    if action == ShellAction.FLAG:
        # monitor-mode: would_have_blocked is recorded; let through as flag
        reason_parts = [f.reason for f in shell_result.findings[:3]]
        return Decision("flag", "; ".join(reason_parts) or "Shell command flagged by policy", rule_ids)

    # allow
    return Decision("allow", base.reason, base.rule_ids + rule_ids)


def _safe_block_reason(categories: list[str], findings: list) -> str:
    """Return a useful-to-LLM reason that does not reveal detection internals."""
    if not categories:
        return "Shell command blocked by policy"
    human = {
        "destructive_filesystem": "destructive filesystem operation",
        "privilege_escalation": "privilege escalation",
        "download_execute": "remote download-and-execute",
        "reverse_shell": "reverse shell or tunnel",
        "persistence": "persistence mechanism",
        "credential_access": "credential or secret access",
        "data_exfiltration": "data exfiltration",
        "security_tampering": "security control tampering",
        "resource_exhaustion": "resource exhaustion (fork bomb)",
        "supply_chain": "supply-chain risk",
        "network_recon": "network reconnaissance",
        "dynamic_execution": "dynamic or unanalyzable execution",
    }
    mapped = [human.get(c, c) for c in categories[:2]]
    return f"Shell command blocked by policy: {', '.join(mapped)} detected"


def _attach_shell_metadata(event: InterceptionEvent, shell_result: Any) -> None:
    """Attach shell analysis results to event payload for observability."""
    try:
        summary = {
            "normalized_command": shell_result.normalized_summary,
            "shell_severity": shell_result.severity.value if hasattr(shell_result.severity, "value") else str(shell_result.severity),
            "shell_rule_ids": shell_result.rule_ids,
            "attack_techniques": shell_result.attack_techniques,
            "categories": list({f.category for f in shell_result.findings}),
            "would_have_blocked": shell_result.would_have_blocked,
        }
        event.payload["shell_analysis"] = summary
    except Exception:
        pass


def _parse_workspace_roots(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(r) for r in raw]
    if isinstance(raw, str):
        import json
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(r) for r in parsed]
        except Exception:
            return [raw]
    return []


def install() -> None:
    """Replace the default decision hook with the shell-policy-aware one."""
    import mcp_interception

    mcp_interception.decision_hook = shell_policy_decision_hook
    logger.info("Shell policy decision hook installed")
