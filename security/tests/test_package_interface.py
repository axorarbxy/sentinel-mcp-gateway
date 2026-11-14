import subprocess
import sys
from pathlib import Path

import pytest

import security


def test_importing_package_is_lazy():
    command = (
        "import sys, security; "
        "assert 'security.auth' not in sys.modules; "
        "assert 'security.shell_analysis' not in sys.modules; "
        "assert 'fastapi' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", command], check=True, cwd=Path(__file__).parents[2])


def test_missing_route_dependency_is_reported():
    command = """
import importlib.abc
import security
import sys

class BlockFastAPI(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "fastapi" or fullname.startswith("fastapi."):
            raise ModuleNotFoundError("No module named 'fastapi'", name="fastapi")

sys.meta_path.insert(0, BlockFastAPI())
try:
    security.auth_router
except ModuleNotFoundError as error:
    assert error.name == "fastapi"
else:
    raise AssertionError("A missing route dependency was silently ignored")
"""
    subprocess.run([sys.executable, "-c", command], check=True, cwd=Path(__file__).parents[2])


def test_all_public_exports_resolve():
    for name in security.__all__:
        assert getattr(security, name) is not None, name


def test_legacy_and_package_auth_imports_share_identity():
    from auth import create_access_token
    from security import create_access_token as package_create_access_token

    assert package_create_access_token is create_access_token


def test_subsystem_discovery_and_loading():
    assert {"auth", "policies", "shell_analysis", "sqli_policy"} <= set(security.discover_modules())
    policy = security.load_subsystem("policy")
    assert policy["PolicyEngine"] is security.PolicyEngine
    assert policy["check_path_traversal"] is security.check_path_traversal
    with pytest.raises(ValueError, match="Unknown security subsystem"):
        security.load_subsystem("unknown")


def test_authentication_and_policy_exports():
    key, lookup_id, prefix = security.create_agent_api_key()
    assert security.parse_agent_api_key(key) == (lookup_id, key)
    assert prefix in key
    assert security.verify_api_key(key, security.hash_api_key(key))
    hashed = security.get_password_hash("S3cure-test-password")
    assert security.verify_password("S3cure-test-password", hashed)
    assert not security.verify_password("incorrect", hashed)

    decision = security.PolicyEngine().evaluate("tools/call", {"name": "read_file", "arguments": {"path": "notes.txt"}})
    assert decision.action is security.PolicyAction.ALLOW


def test_shell_and_sql_exports_resolve():
    assert security.is_shell_tool("shell")
    assert security.analyse_tool_call("read_file", {"path": "notes.txt"}) is None
    assert callable(security.shell_policy_decision_hook)
    assert callable(security.install_shell_policy)

    result = security.analyze_sql_injection(
        {"query": "SELECT name FROM users"},
        sql_mode="readonly",
    )
    assert result["detector"] == "sqli"
    assert result["action"] == "allow"
    assert security.list_sqli_indicators()


def test_configuration_validation_does_not_expose_secret():
    assert security.validate_security_configuration({"SENTINEL_ENVIRONMENT": "production"}) == (
        "SECRET_KEY must be configured in production.",
    )
    assert security.validate_security_configuration({
        "SENTINEL_ENVIRONMENT": "production",
        "SECRET_KEY": "x" * 31,
    }) == ("SECRET_KEY must contain at least 32 UTF-8 bytes in production.",)
    assert security.validate_security_configuration({
        "SENTINEL_ENVIRONMENT": "production",
        "SECRET_KEY": "x" * 32,
    }) == ()
