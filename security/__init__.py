"""Public, lazily loaded interface for Sentinel's security subsystems.

The implementation remains in the focused modules in this package. Importing
``security`` alone does not load authentication providers, API routes, or the
shell-analysis engine. Public names are resolved on first access and re-use
the gateway's legacy top-level modules when those are already loaded.

Subsystems:

* ``authentication``: password, JWT, API-key, and OAuth-scope interfaces.
* ``authorization``: OAuth scopes, ACL checks, and policy decisions.
* ``policy``: request, path-traversal, shell-command, and SQL-safety checks.
* ``shell``: shell analysis and its MCP decision-hook integration.
* ``sql``: SQL-injection analysis, indicator configuration, and policy routes.
"""

from __future__ import annotations

import os
import sys
from importlib import import_module, metadata, resources
from types import MappingProxyType, ModuleType
from typing import Any, Mapping

try:
    __version__ = metadata.version("sentinel-mcp-gateway")
except metadata.PackageNotFoundError:
    __version__ = "0+unknown"

CAPABILITIES: Mapping[str, str] = MappingProxyType({
    "authentication": "Password hashing, JWTs, and agent/user API-key helpers.",
    "authorization": "OAuth scopes, tool ACL checks, and aggregate policy decisions.",
    "policy": "MCP request, path traversal, legacy shell, and read-only SQL checks.",
    "shell": "Shell command analysis and MCP decision-hook integration.",
    "sql": "SQL-injection analysis, indicator metadata, and SQL policy routes.",
})

SUBSYSTEMS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "authentication": (
        "ALGORITHM", "ACCESS_TOKEN_EXPIRE_MINUTES", "REFRESH_TOKEN_EXPIRE_DAYS",
        "AGENT_KEY_PATTERN", "is_demo_environment", "create_agent_api_key",
        "parse_agent_api_key", "truncate_password", "verify_password",
        "get_password_hash", "create_access_token", "create_refresh_token",
        "decode_token", "get_current_user", "hash_api_key", "verify_api_key",
        "OAUTH_SCOPES", "oauth2_scheme", "require_scopes", "auth_router",
        "UserCreate", "UserLogin", "TokenResponse", "UserResponse", "APIKeyCreate",
        "create_api_key", "list_api_keys", "login", "refresh_token", "register",
    ),
    "authorization": (
        "OAUTH_SCOPES", "oauth2_scheme", "require_scopes", "DEFAULT_ACL",
        "PolicyAction", "PolicyDecision", "PolicyEngine", "check_acl",
    ),
    "policy": (
        "PolicyResult", "PolicyDecision", "PolicyAction", "PolicyEngine",
        "DEFAULT_ACL", "SENSITIVE_PATHS", "PATH_TRAVERSAL_PATTERNS",
        "check_acl", "check_path_traversal", "check_shell_command",
        "check_sql_query", "evaluate",
    ),
    "shell": (
        "RiskLevel", "ShellAction", "ShellFinding", "ShellAnalysisResult",
        "ShellCommandAnalyser", "is_shell_tool", "extract_shell_commands",
        "analyse_tool_call", "KNOWN_LIMITATIONS", "MAX_COMMAND_BYTES",
        "shell_policy_decision_hook", "install_shell_policy",
    ),
    "sql": (
        "MAX_ANALYZED_CHARS", "MAX_FIELDS", "MAX_DEPTH", "CALL_BUDGET_MS",
        "DEFAULT_TOOL_MODES", "QUERY_TOOL_INDICATORS", "list_sqli_indicators",
        "normalize_sql_text", "extract_string_values", "resolve_sql_mode",
        "analyze_sql_injection", "get_runtime_configuration",
        "get_agent_policy_metadata", "sqli_router", "IndicatorUpdate",
        "SQLiTestRequest",
    ),
})

_EXPORTS: dict[str, tuple[str, str]] = {
    # Authentication and identity helpers.
    "AGENT_KEY_PATTERN": ("auth", "AGENT_KEY_PATTERN"),
    "ALGORITHM": ("auth", "ALGORITHM"),
    "ACCESS_TOKEN_EXPIRE_MINUTES": ("auth", "ACCESS_TOKEN_EXPIRE_MINUTES"),
    "REFRESH_TOKEN_EXPIRE_DAYS": ("auth", "REFRESH_TOKEN_EXPIRE_DAYS"),
    "is_demo_environment": ("auth", "is_demo_environment"),
    "create_agent_api_key": ("auth", "create_agent_api_key"),
    "parse_agent_api_key": ("auth", "parse_agent_api_key"),
    "truncate_password": ("auth", "truncate_password"),
    "verify_password": ("auth", "verify_password"),
    "get_password_hash": ("auth", "get_password_hash"),
    "create_access_token": ("auth", "create_access_token"),
    "create_refresh_token": ("auth", "create_refresh_token"),
    "decode_token": ("auth", "decode_token"),
    "get_current_user": ("auth", "get_current_user"),
    "hash_api_key": ("auth", "hash_api_key"),
    "verify_api_key": ("auth", "verify_api_key"),
    "OAUTH_SCOPES": ("auth_routes", "OAUTH_SCOPES"),
    "oauth2_scheme": ("auth_routes", "oauth2_scheme"),
    "require_scopes": ("auth_routes", "require_scopes"),
    "auth_router": ("auth_routes", "router"),
    "UserCreate": ("auth_routes", "UserCreate"),
    "UserLogin": ("auth_routes", "UserLogin"),
    "TokenResponse": ("auth_routes", "TokenResponse"),
    "UserResponse": ("auth_routes", "UserResponse"),
    "APIKeyCreate": ("auth_routes", "APIKeyCreate"),
    "create_api_key": ("auth_routes", "create_api_key"),
    "list_api_keys": ("auth_routes", "list_api_keys"),
    "login": ("auth_routes", "login"),
    "refresh_token": ("auth_routes", "refresh_token"),
    "register": ("auth_routes", "register"),
    # Authorization and general policy.
    "PolicyResult": ("policies", "PolicyResult"),
    "PolicyAction": ("policies", "PolicyAction"),
    "PolicyDecision": ("policies", "PolicyDecision"),
    "SENSITIVE_PATHS": ("policies", "SENSITIVE_PATHS"),
    "PATH_TRAVERSAL_PATTERNS": ("policies", "PATH_TRAVERSAL_PATTERNS"),
    "DEFAULT_ACL": ("policies", "DEFAULT_ACL"),
    "check_path_traversal": ("policies", "check_path_traversal"),
    "check_acl": ("policies", "check_acl"),
    "check_shell_command": ("policies", "check_shell_command"),
    "check_sql_query": ("policies", "check_sql_query"),
    "evaluate": ("policies", "evaluate"),
    "PolicyEngine": ("policies", "PolicyEngine"),
    # Shell analysis and MCP interception integration.
    "RiskLevel": ("shell_analysis", "RiskLevel"),
    "ShellAction": ("shell_analysis", "ShellAction"),
    "ShellFinding": ("shell_analysis", "ShellFinding"),
    "ShellAnalysisResult": ("shell_analysis", "ShellAnalysisResult"),
    "ShellCommandAnalyser": ("shell_analysis", "ShellCommandAnalyser"),
    "is_shell_tool": ("shell_analysis", "is_shell_tool"),
    "extract_shell_commands": ("shell_analysis", "extract_shell_commands"),
    "analyse_tool_call": ("shell_analysis", "analyse_tool_call"),
    "KNOWN_LIMITATIONS": ("shell_analysis", "KNOWN_LIMITATIONS"),
    "MAX_COMMAND_BYTES": ("shell_analysis", "MAX_COMMAND_BYTES"),
    "shell_policy_decision_hook": ("shell_policy_hook", "shell_policy_decision_hook"),
    "install_shell_policy": ("shell_policy_hook", "install"),
    # SQL analysis and management.
    "MAX_ANALYZED_CHARS": ("sqli_policy", "MAX_ANALYZED_CHARS"),
    "MAX_FIELDS": ("sqli_policy", "MAX_FIELDS"),
    "MAX_DEPTH": ("sqli_policy", "MAX_DEPTH"),
    "CALL_BUDGET_MS": ("sqli_policy", "CALL_BUDGET_MS"),
    "DEFAULT_TOOL_MODES": ("sqli_policy", "DEFAULT_TOOL_MODES"),
    "QUERY_TOOL_INDICATORS": ("sqli_policy", "QUERY_TOOL_INDICATORS"),
    "list_sqli_indicators": ("sqli_policy", "list_sqli_indicators"),
    "normalize_sql_text": ("sqli_policy", "normalize_sql_text"),
    "extract_string_values": ("sqli_policy", "extract_string_values"),
    "resolve_sql_mode": ("sqli_policy", "resolve_sql_mode"),
    "analyze_sql_injection": ("sqli_policy", "analyze_sql_injection"),
    "get_runtime_configuration": ("sqli_policy", "get_runtime_configuration"),
    "get_agent_policy_metadata": ("sqli_policy", "get_agent_policy_metadata"),
    "sqli_router": ("sqli_routes", "router"),
    "IndicatorUpdate": ("sqli_routes", "IndicatorUpdate"),
    "SQLiTestRequest": ("sqli_routes", "SQLiTestRequest"),
}

_MODULE_DEPENDENCIES: Mapping[str, tuple[str, ...]] = {
    "auth_routes": ("auth",),
    "sqli_routes": ("auth", "auth_routes", "sqli_policy"),
    "shell_policy_hook": ("shell_analysis",),
}


def _load_module(module_name: str) -> ModuleType:
    """Load a package subsystem while preserving legacy gateway module identity."""
    for dependency in _MODULE_DEPENDENCIES.get(module_name, ()):
        _load_module(dependency)

    qualified_name = f"{__name__}.{module_name}"
    module = sys.modules.get(module_name) or sys.modules.get(qualified_name)
    if module is None:
        module = import_module(f".{module_name}", __name__)

    sys.modules.setdefault(module_name, module)
    sys.modules.setdefault(qualified_name, module)
    return module


def __getattr__(name: str) -> Any:
    """Resolve a public subsystem symbol on demand."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, attribute_name = target
    value = getattr(_load_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Include lazy public names in interactive package inspection."""
    return sorted(set(globals()) | set(__all__))


def discover_modules() -> tuple[str, ...]:
    """Return importable Python modules physically present in this package."""
    return tuple(sorted(
        entry.name[:-3]
        for entry in resources.files(__name__).iterdir()
        if entry.name.endswith(".py")
        and entry.name != "__init__.py"
        and not entry.name.startswith("_")
    ))


def load_subsystem(name: str) -> Mapping[str, Any]:
    """Load one documented subsystem and return its public symbols by name.

    Raises ``ValueError`` for unknown subsystem names. Import and dependency
    errors from an installed subsystem are allowed to propagate to the caller.
    """
    try:
        exports = SUBSYSTEMS[name]
    except KeyError:
        known = ", ".join(sorted(SUBSYSTEMS))
        raise ValueError(f"Unknown security subsystem {name!r}; choose from: {known}") from None
    return MappingProxyType({export: getattr(sys.modules[__name__], export) for export in exports})


def validate_security_configuration(
    environ: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Return actionable JWT-secret configuration errors without exposing secrets.

    Production deployments must provide ``SECRET_KEY`` with at least 32 UTF-8
    bytes. Development and test environments may rely on the existing
    per-process fallback in :mod:`security.auth`. The returned tuple is empty
    when this check passes.
    """
    values = os.environ if environ is None else environ
    environment = values.get("SENTINEL_ENVIRONMENT", "dev").strip().lower()
    secret = values.get("SECRET_KEY", "")
    if environment in {"prod", "production"}:
        if not secret:
            return ("SECRET_KEY must be configured in production.",)
        if len(secret.encode("utf-8")) < 32:
            return ("SECRET_KEY must contain at least 32 UTF-8 bytes in production.",)
    return ()


__all__ = [
    "__version__",
    "CAPABILITIES",
    "SUBSYSTEMS",
    "discover_modules",
    "load_subsystem",
    "validate_security_configuration",
    *_EXPORTS,
]
