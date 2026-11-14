"""Security package public interface for Sentinel MCP Gateway.

This package exposes authentication, authorization, request policies, shell
analysis, and SQL-injection controls through lazy imports. Implementations
remain in their focused modules; importing ``security`` does not eagerly load
FastAPI, SQLAlchemy, bcrypt, JWT libraries, or the shell analysis engine.

Security guidance:
* Apply authorization checks to every protected operation.
* Prefer explicit OAuth scopes over client-supplied role flags.
* Configure stable JWT signing secrets outside source control.
* Never log passwords, bearer tokens, API keys, or raw sensitive payloads.
* Treat static analysis as one layer in a defence-in-depth design.
* Use parameterized database operations; pattern detection is not a substitute.
* Review the documented limitations of shell and SQL analysis modules.

Example::

    from security import PolicyEngine, analyze_sql_injection
    from security.auth import create_access_token
"""

from __future__ import annotations

from importlib import import_module
from typing import Any, Final

__version__: Final[str] = "1.0.0"
__title__: Final[str] = "Sentinel MCP Gateway Security"
__description__: Final[str] = (
    "Authentication, authorization, policy enforcement, and security controls."
)

# Public symbols are mapped explicitly to their source modules. This keeps
# the package interface auditable and avoids importing optional stacks early.
_EXPORTS: Final[dict[str, tuple[str, str]]] = {
    # Authentication primitives.
    "AGENT_KEY_PATTERN": ("security.auth", "AGENT_KEY_PATTERN"),
    "SECRET_KEY": ("security.auth", "SECRET_KEY"),
    "ALGORITHM": ("security.auth", "ALGORITHM"),
    "ACCESS_TOKEN_EXPIRE_MINUTES": ("security.auth", "ACCESS_TOKEN_EXPIRE_MINUTES"),
    "REFRESH_TOKEN_EXPIRE_DAYS": ("security.auth", "REFRESH_TOKEN_EXPIRE_DAYS"),
    "is_demo_environment": ("security.auth", "is_demo_environment"),
    "create_agent_api_key": ("security.auth", "create_agent_api_key"),
    "parse_agent_api_key": ("security.auth", "parse_agent_api_key"),
    "truncate_password": ("security.auth", "truncate_password"),
    "verify_password": ("security.auth", "verify_password"),
    "get_password_hash": ("security.auth", "get_password_hash"),
    "create_access_token": ("security.auth", "create_access_token"),
    "create_refresh_token": ("security.auth", "create_refresh_token"),
    "decode_token": ("security.auth", "decode_token"),
    "get_current_user": ("security.auth", "get_current_user"),
    "hash_api_key": ("security.auth", "hash_api_key"),
    "verify_api_key": ("security.auth", "verify_api_key"),

    # Optional FastAPI authentication router and schemas.
    "auth_router": ("security.auth_routes", "router"),
    "UserCreate": ("security.auth_routes", "UserCreate"),
    "UserLogin": ("security.auth_routes", "UserLogin"),
    "TokenResponse": ("security.auth_routes", "TokenResponse"),
    "UserResponse": ("security.auth_routes", "UserResponse"),
    "APIKeyCreate": ("security.auth_routes", "APIKeyCreate"),
    "OAUTH_SCOPES": ("security.auth_routes", "OAUTH_SCOPES"),
    "oauth2_scheme": ("security.auth_routes", "oauth2_scheme"),
    "require_scopes": ("security.auth_routes", "require_scopes"),

    # MCP request policy engine.
    "PolicyResult": ("security.policies", "PolicyResult"),
    "PolicyAction": ("security.policies", "PolicyAction"),
    "PolicyDecision": ("security.policies", "PolicyDecision"),
    "SENSITIVE_PATHS": ("security.policies", "SENSITIVE_PATHS"),
    "PATH_TRAVERSAL_PATTERNS": ("security.policies", "PATH_TRAVERSAL_PATTERNS"),
    "DEFAULT_ACL": ("security.policies", "DEFAULT_ACL"),
    "check_path_traversal": ("security.policies", "check_path_traversal"),
    "check_acl": ("security.policies", "check_acl"),
    "check_shell_command": ("security.policies", "check_shell_command"),
    "check_sql_query": ("security.policies", "check_sql_query"),
    "evaluate": ("security.policies", "evaluate"),
    "PolicyEngine": ("security.policies", "PolicyEngine"),

    # Static shell analysis and MCP interception integration.
    "RiskLevel": ("security.shell_analysis", "RiskLevel"),
    "ShellAction": ("security.shell_analysis", "ShellAction"),
    "ShellFinding": ("security.shell_analysis", "ShellFinding"),
    "ShellAnalysisResult": ("security.shell_analysis", "ShellAnalysisResult"),
    "ShellCommandAnalyser": ("security.shell_analysis", "ShellCommandAnalyser"),
    "is_shell_tool": ("security.shell_analysis", "is_shell_tool"),
    "extract_shell_commands": ("security.shell_analysis", "extract_shell_commands"),
    "analyse_tool_call": ("security.shell_analysis", "analyse_tool_call"),
    "shell_policy_decision_hook": ("security.shell_policy_hook", "shell_policy_decision_hook"),
    "install_shell_policy_hook": ("security.shell_policy_hook", "install"),

    # SQL-injection analysis and runtime configuration.
    "MAX_ANALYZED_CHARS": ("security.sqli_policy", "MAX_ANALYZED_CHARS"),
    "MAX_FIELDS": ("security.sqli_policy", "MAX_FIELDS"),
    "MAX_DEPTH": ("security.sqli_policy", "MAX_DEPTH"),
    "CALL_BUDGET_MS": ("security.sqli_policy", "CALL_BUDGET_MS"),
    "DEFAULT_TOOL_MODES": ("security.sqli_policy", "DEFAULT_TOOL_MODES"),
    "list_sqli_indicators": ("security.sqli_policy", "list_sqli_indicators"),
    "normalize_sql_text": ("security.sqli_policy", "normalize_sql_text"),
    "extract_string_values": ("security.sqli_policy", "extract_string_values"),
    "resolve_sql_mode": ("security.sqli_policy", "resolve_sql_mode"),
    "sql_ml_features": ("security.sqli_policy", "sql_ml_features"),
    "analyze_sql_injection": ("security.sqli_policy", "analyze_sql_injection"),
    "get_runtime_configuration": ("security.sqli_policy", "get_runtime_configuration"),
    "get_agent_policy_metadata": ("security.sqli_policy", "get_agent_policy_metadata"),

    # Optional FastAPI SQL-injection policy router and schemas.
    "sqli_router": ("security.sqli_routes", "router"),
    "IndicatorUpdate": ("security.sqli_routes", "IndicatorUpdate"),
    "SQLiTestRequest": ("security.sqli_routes", "SQLiTestRequest"),
}

__all__: Final[tuple[str, ...]] = (
    "__version__", "__title__", "__description__", *_EXPORTS.keys()
)


def __getattr__(name: str) -> Any:
    """Resolve a declared public symbol only when it is first accessed.

    Optional dependency errors are deliberately propagated. Callers therefore
    receive the original diagnostic rather than a misleading missing-symbol
    error when a subsystem dependency has not been installed.
    """
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        ) from exc
    module = import_module(module_name)
    value = getattr(module, attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Include lazily exported names in interactive help and IDE completion."""
    return sorted(set(globals()) | set(__all__))


def load_subsystem(name: str) -> Any:
    """Import and return a known subsystem by its short module name.

    Supported names: ``auth``, ``auth_routes``, ``policies``,
    ``shell_analysis``, ``shell_policy_hook``, ``sqli_policy``, and
    ``sqli_routes``. Unknown names raise ``ValueError``.
    """
    modules = {
        "auth": "security.auth",
        "auth_routes": "security.auth_routes",
        "policies": "security.policies",
        "shell_analysis": "security.shell_analysis",
        "shell_policy_hook": "security.shell_policy_hook",
        "sqli_policy": "security.sqli_policy",
        "sqli_routes": "security.sqli_routes",
    }
    try:
        module_name = modules[name]
    except KeyError as exc:
        available = ", ".join(sorted(modules))
        raise ValueError(f"Unknown subsystem {name!r}. Available: {available}") from exc
    return import_module(module_name)


def subsystem_status() -> dict[str, dict[str, Any]]:
    """Report whether each package source module can be located.

    This checks module presence only; it does not claim that dependencies are
    installed or that a particular security control is active at runtime.
    """
    from importlib.util import find_spec

    modules = {
        "auth": "security.auth",
        "auth_routes": "security.auth_routes",
        "policies": "security.policies",
        "shell_analysis": "security.shell_analysis",
        "shell_policy_hook": "security.shell_policy_hook",
        "sqli_policy": "security.sqli_policy",
        "sqli_routes": "security.sqli_routes",
    }
    status: dict[str, dict[str, Any]] = {}
    for short_name, module_name in modules.items():
        try:
            available = find_spec(module_name) is not None
        except (ImportError, ModuleNotFoundError, ValueError):
            available = False
        status[short_name] = {"module": module_name, "available": available}
    return status


def security_capabilities() -> dict[str, Any]:
    """Return a descriptive, machine-readable security capability summary.

    Capability labels describe implemented subsystems; they are not a runtime
    attestation and do not mean that any individual request has been approved.
    """
    return {
        "package": __title__,
        "version": __version__,
        "capabilities": {
            "authentication": [
                "password_hashing", "jwt_access_and_refresh_tokens",
                "agent_api_key_generation", "api_key_hashing_and_verification",
            ],
            "authorization": ["oauth_scope_enforcement", "tool_access_control_list"],
            "request_policies": [
                "path_traversal_detection", "sensitive_path_detection",
                "legacy_shell_command_allowlist", "read_only_sql_safety_check",
            ],
            "shell_security": [
                "static_shell_command_analysis", "mcp_interception_decision_hook",
            ],
            "database_query_security": [
                "sql_injection_indicator_analysis", "sql_mode_resolution",
                "runtime_policy_configuration",
            ],
        },
        "subsystems": subsystem_status(),
    }


def validate_security_configuration() -> list[dict[str, str]]:
    """Return advisory configuration warnings without revealing secret values.

    Production must supply a stable signing key through its environment or a
    secret manager. Development mode is explicitly identified because the
    existing authentication module enables demo-only operator privileges there.
    """
    import os

    warnings: list[dict[str, str]] = []
    environment = os.getenv("SENTINEL_ENVIRONMENT", "dev").strip().lower()
    if environment in {"prod", "production"}:
        if not os.getenv("SECRET_KEY"):
            warnings.append({
                "code": "AUTH_SECRET_NOT_CONFIGURED",
                "severity": "critical",
                "message": (
                    "SECRET_KEY is unset. Configure a stable, high-entropy JWT signing "
                    "secret through the deployment secret manager."
                ),
            })
    else:
        warnings.append({
            "code": "NON_PRODUCTION_ENVIRONMENT",
            "severity": "info",
            "message": (
                "The configured environment is not production. Verify that "
                "demo-only privileges and development credentials are not exposed."
            ),
        })
    return warnings


# End of package public interface.