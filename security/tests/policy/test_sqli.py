from __future__ import annotations

import json
import time
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from sqli_policy import analyze_sql_injection, normalize_sql_text


CASES = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "sqli_cases.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES)
def test_fixture_cases(case):
    payload = case["payload"] * case.get("repeat", 1)
    result = analyze_sql_injection(payload, sql_mode=case["sql_mode"])
    matched_ids = {finding["id"] for finding in result["findings"]}
    assert result["action"] == case["expected_action"]
    assert set(case["expected_ids"]).issubset(matched_ids)


def test_normalizer_decodes_double_url_encoding_and_sql_literals():
    forms = normalize_sql_text("SeLeCt%2520CHAR(85,78,73,79,78)")
    assert "select union" in forms["decoded"]


def test_nested_arguments_include_field_paths_and_ignore_nulls():
    result = analyze_sql_injection({"query": {"filter": [None, "1 UNION SELECT password FROM users"]}})
    finding = next(item for item in result["findings"] if item["id"] == "SQLI-003")
    assert finding["field_path"] == "arguments.query.filter[1]"


def test_sensitive_evidence_is_redacted_and_truncated():
    payload = {"query": "SELECT * FROM users WHERE token=super-secret-value UNION SELECT password FROM users"}
    result = analyze_sql_injection(payload)
    evidence = " ".join(item["evidence"] for item in result["findings"])
    assert "super-secret-value" not in evidence
    assert all(len(item["evidence"]) <= 120 for item in result["findings"])


def test_oversized_input_is_capped_and_low_severity():
    result = analyze_sql_injection("x" * 20_000)
    finding = next(item for item in result["findings"] if item["id"] == "SQLI-015")
    assert finding["severity"] == "low"
    assert result["action"] == "allow"


def test_binary_looking_input_and_null_values_are_ignored():
    result = analyze_sql_injection({"binary": "\x00\x01\x02\xff", "nothing": None})
    assert result["findings"] == []


def test_time_budget_is_enforced_fail_closed():
    started = time.perf_counter()
    result = analyze_sql_injection("SELECT " + "x " * 100, budget_ms=0)
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert result["action"] == "block"
    assert result["findings"][0]["id"] == "SQLI-ENGINE-TIMEOUT"
    assert elapsed_ms < 100


def test_agent_mode_override_and_indicator_allowlist():
    agent = {
        "metadata": {
            "sql_mode_overrides": {"db/query": "query_tool"},
            "sqli_allowlist": ["SQLI-001"],
        }
    }
    result = analyze_sql_injection("' OR 1=1", tool_name="db/query", agent=agent)
    assert result["sql_mode"] == "query_tool"
    assert result["action"] == "allow"
    assert result["findings"][0]["overridden"] is True