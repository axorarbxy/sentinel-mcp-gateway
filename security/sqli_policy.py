from __future__ import annotations

import json
import re
import time
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import unquote


MAX_ANALYZED_CHARS = 10_000
MAX_FIELDS = 256
MAX_DEPTH = 32
CALL_BUDGET_MS = 100.0
SEVERITY_WEIGHT = {"high": 0.9, "medium": 0.5, "low": 0.2}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
DEFAULT_TOOL_MODES = {"db/query": "readonly", "database/query": "query_tool", "sql/query": "query_tool"}
QUERY_TOOL_INDICATORS = {
    "SQLI-001", "SQLI-004", "SQLI-005", "SQLI-006", "SQLI-008", "SQLI-010", "SQLI-014",
}
SQL_KEYWORDS = {
    "select", "from", "where", "and", "or", "union", "insert", "update", "delete", "set",
    "drop", "alter", "truncate", "exec", "into", "join", "having", "order", "group",
}
SQL_STATEMENT_RE = re.compile(r"^\s*(select|insert|update|delete|drop|alter|truncate|exec(?:ute)?)\b", re.I)
SQL_START_RE = re.compile(r"^\s*select\b", re.I)
SQL_KEYWORD_RE = re.compile(r"\b(" + "|".join(sorted(SQL_KEYWORDS)) + r")\b", re.I)
PERCENT_ENCODING_RE = re.compile(r"%[0-9a-f]{2}", re.I)
HEX_LITERAL_RE = re.compile(r"\b0x([0-9a-f]{4,64})\b", re.I)
CHAR_CALL_RE = re.compile(r"\b(?:char|chr)\s*\(\s*(\d{1,3}(?:\s*,\s*\d{1,3}){1,31})\s*\)", re.I)
ZERO_WIDTH_RE = re.compile("[\\u200b-\\u200f\\u202a-\\u202e\\u2060\\ufeff]")
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
WHITESPACE_RE = re.compile(r"\s+")
SECRET_EVIDENCE_RE = re.compile(
    r"(?i)(\b(?:password|passwd|secret|token|credential|api[_-]?key|authorization)\b\s*[:=]\s*)[^\s,;&]+|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]+"
)
_CATALOG = json.loads((Path(__file__).with_name("sqli_indicators.json")).read_text(encoding="utf-8"))
_INDICATORS = []
for _entry in _CATALOG["indicators"]:
    _compiled = dict(_entry)
    _compiled["_patterns"] = [re.compile(pattern, re.I) for pattern in _entry.get("patterns", [])]
    _INDICATORS.append(_compiled)


def list_sqli_indicators() -> list[dict[str, Any]]:
    return [
        {
            "id": item["id"],
            "name": item["name"],
            "description": item["description"],
            "severity": item["severity"],
            "category": item["category"],
            "recommendation": item["recommendation"],
        }
        for item in _INDICATORS
    ]


def _basic_normalize(value: str, *, remove_comments: bool) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    normalized = ZERO_WIDTH_RE.sub("", normalized).lower()
    if remove_comments:
        normalized = BLOCK_COMMENT_RE.sub(" ", normalized)
    return WHITESPACE_RE.sub(" ", normalized).strip()


def _decode_sql_literals(value: str) -> str:
    def decode_hex(match: re.Match[str]) -> str:
        digits = match.group(1)
        if len(digits) % 2:
            return match.group(0)
        try:
            decoded = bytes.fromhex(digits).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return match.group(0)
        return decoded if decoded.isprintable() else match.group(0)

    def decode_char(match: re.Match[str]) -> str:
        try:
            decoded = "".join(chr(int(part)) for part in re.split(r"\s*,\s*", match.group(1)))
        except (ValueError, OverflowError):
            return match.group(0)
        return decoded if all(char.isprintable() for char in decoded) else match.group(0)

    decoded = HEX_LITERAL_RE.sub(decode_hex, value)
    return CHAR_CALL_RE.sub(decode_char, decoded)


def normalize_sql_text(value: str) -> dict[str, str]:
    """Return raw-normalized and repeatedly URL-decoded SQL matching forms."""
    raw_form = _basic_normalize(value[:MAX_ANALYZED_CHARS], remove_comments=False)
    decoded = value[:MAX_ANALYZED_CHARS]
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    normalized = _basic_normalize(decoded, remove_comments=True)
    literal_decoded = _basic_normalize(_decode_sql_literals(normalized), remove_comments=True)
    return {"raw": raw_form, "normalized": normalized, "decoded": literal_decoded}


def extract_string_values(value: Any, path: str = "arguments", depth: int = 0):
    """Yield (field_path, string) pairs from nested mappings and lists."""
    if depth > MAX_DEPTH:
        return
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            yield from extract_string_values(item, child_path, depth + 1)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from extract_string_values(item, f"{path}[{index}]", depth + 1)


def _safe_evidence(value: str, start: int = 0, end: int | None = None) -> str:
    end = len(value) if end is None else end
    left = max(0, start - 45)
    right = min(len(value), max(end, start + 1) + 75)
    evidence = value[left:right].replace("\x00", "")
    evidence = SECRET_EVIDENCE_RE.sub(lambda match: f"{match.group(1) or 'Bearer '}[REDACTED]", evidence)
    if len(evidence) > 120:
        evidence = evidence[:117] + "..."
    return evidence


def _metadata(agent: dict[str, Any] | None) -> dict[str, Any]:
    if not agent:
        return {}
    raw = agent.get("metadata", {})
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            raw = {}
    return raw if isinstance(raw, dict) else {}


def resolve_sql_mode(
    tool_name: str | None,
    *,
    explicit_mode: str | None = None,
    agent: dict[str, Any] | None = None,
    tool_modes: dict[str, str] | None = None,
) -> str:
    if explicit_mode is not None:
        mode = explicit_mode
    else:
        metadata = _metadata(agent)
        overrides = agent.get("sql_mode_overrides", metadata.get("sql_mode_overrides", {})) if agent else {}
        configured_modes = {**_CATALOG.get("tool_modes", DEFAULT_TOOL_MODES), **(tool_modes or {})}
        mode = overrides.get(tool_name, configured_modes.get(tool_name, "none")) if isinstance(overrides, dict) else configured_modes.get(tool_name, "none")
        role = str(metadata.get("role", "")).strip().lower().replace("-", "_")
        if role in {"readonly", "read_only"}:
            mode = "readonly"
    if mode not in {"none", "query_tool", "readonly"}:
        raise ValueError("sql_mode must be none, query_tool, or readonly")
    return mode


def _finding(indicator: dict[str, Any], severity: str, field_path: str, evidence: str) -> dict[str, Any]:
    return {
        "id": indicator["id"],
        "name": indicator["name"],
        "description": indicator["description"],
        "severity": severity,
        "category": indicator["category"],
        "field_path": field_path,
        "evidence": _safe_evidence(evidence),
        "recommendation": indicator["recommendation"],
    }


def _match_indicator(indicator: dict[str, Any], forms: dict[str, str], mode: str):
    matcher = indicator.get("matcher")
    if matcher == "encoding_evasion":
        raw = forms["raw"]
        normalized = forms["normalized"]
        encoded_count = len(PERCENT_ENCODING_RE.findall(raw))
        if encoded_count >= 3 and SQL_KEYWORD_RE.search(normalized):
            return raw, PERCENT_ENCODING_RE.search(raw)
        for candidate in (forms["raw"], forms["decoded"]):
            match = re.search(r"\b(?:select|where|or|and)\b.{0,80}\b0x[0-9a-f]{4,64}\b", candidate, re.I)
            if match:
                return candidate, match
        match = CHAR_CALL_RE.search(forms["raw"])
        return (forms["raw"], match) if match else None
    if matcher == "quote_anomaly":
        for candidate in (forms["raw"], forms["normalized"]):
            if candidate.count("'") % 2 or candidate.count('"') % 2:
                if len(set(SQL_KEYWORD_RE.findall(candidate))) >= 2:
                    return candidate, None
        return None
    if matcher == "keyword_density":
        if mode != "none":
            return None
        candidate = forms["decoded"]
        keywords = set(SQL_KEYWORD_RE.findall(candidate))
        if len(keywords) >= 4:
            return candidate, None
        return None
    if matcher == "readonly_violation":
        if mode != "readonly":
            return None
        candidate = forms["decoded"]
        statement = SQL_STATEMENT_RE.match(candidate)
        with_statement = re.match(r"\s*(?:with|pragma)\b", candidate, re.I)
        if (statement and not SQL_START_RE.match(candidate)) or with_statement:
            return candidate, statement or with_statement
        return None
    for candidate in (forms["raw"], forms["normalized"], forms["decoded"]):
        for pattern in indicator["_patterns"]:
            match = pattern.search(candidate)
            if match:
                return candidate, match
    return None


def _risk_score(findings: list[dict[str, Any]]) -> float:
    product = 1.0
    for finding in findings:
        product *= 1.0 - SEVERITY_WEIGHT[finding["severity"]]
    return round(min(1.0, 1.0 - product), 4)


def _action(findings: list[dict[str, Any]], mode: str) -> str:
    if any(item["severity"] == "high" for item in findings):
        return "block"
    medium_keys = {(item["id"], item["field_path"]) for item in findings if item["severity"] == "medium"}
    if len(medium_keys) >= 2:
        return "block"
    if medium_keys:
        return "flag"
    return "allow"


def sql_ml_features(findings: list[dict[str, Any]], strings: list[str]) -> dict[str, Any]:
    category_counts: dict[str, int] = {}
    for finding in findings:
        category = finding["category"]
        category_counts[category] = category_counts.get(category, 0) + 1
    tokens = [token.lower() for value in strings for token in re.findall(r"[a-z_]+", value[:MAX_ANALYZED_CHARS], re.I)]
    keyword_count = sum(token in SQL_KEYWORDS for token in tokens)
    severities = [item["severity"] for item in findings]
    max_severity = max(severities, key=lambda value: SEVERITY_ORDER[value]) if severities else "none"
    return {
        "category_counts": category_counts,
        "max_severity": max_severity,
        "max_severity_score": SEVERITY_ORDER.get(max_severity, 0),
        "keyword_density": round(keyword_count / max(len(tokens), 1), 6),
    }


def analyze_sql_injection(
    arguments: Any,
    *,
    tool_name: str | None = None,
    sql_mode: str | None = None,
    agent: dict[str, Any] | None = None,
    enabled_overrides: dict[str, bool] | None = None,
    severity_overrides: dict[str, str] | None = None,
    tool_modes: dict[str, str] | None = None,
    budget_ms: float = CALL_BUDGET_MS,
) -> dict[str, Any]:
    """Inspect nested argument strings and return deterministic policy findings."""
    mode = resolve_sql_mode(tool_name, explicit_mode=sql_mode, agent=agent, tool_modes=tool_modes)
    started = time.perf_counter()
    allowlist = set((agent or {}).get("sqli_allowlist", _metadata(agent).get("sqli_allowlist", [])) or [])
    findings: list[dict[str, Any]] = []
    texts: list[str] = []
    timeout = False
    for index, (field_path, original) in enumerate(extract_string_values(arguments)):
        if index >= MAX_FIELDS:
            break
        texts.append(original)
        is_oversized = len(original) > MAX_ANALYZED_CHARS
        forms = normalize_sql_text(original)
        if (time.perf_counter() - started) * 1000 > budget_ms:
            timeout = True
            break
        if is_oversized:
            indicator = next(item for item in _INDICATORS if item["id"] == "SQLI-015")
            findings.append(_finding(indicator, "low", field_path, f"Input exceeded {MAX_ANALYZED_CHARS} characters; analysis truncated"))
        for indicator in _INDICATORS:
            if indicator["id"] == "SQLI-015":
                continue
            if enabled_overrides and enabled_overrides.get(indicator["id"]) is False:
                continue
            if mode == "query_tool" and indicator["id"] not in QUERY_TOOL_INDICATORS:
                continue
            matched = _match_indicator(indicator, forms, mode)
            if matched is None:
                continue
            match_text, match = matched
            start = match.start() if match is not None else 0
            end = match.end() if match is not None else len(match_text)
            severity = (severity_overrides or {}).get(indicator["id"], indicator["severity"]).lower()
            finding = _finding(indicator, severity, field_path, _safe_evidence(match_text, start, end))
            finding["overridden"] = indicator["id"] in allowlist
            findings.append(finding)
            if (time.perf_counter() - started) * 1000 > budget_ms:
                timeout = True
                break
        if timeout:
            break

    if timeout:
        findings = [{
            "id": "SQLI-ENGINE-TIMEOUT",
            "name": "SQLi analysis timeout",
            "description": "SQLi inspection exceeded its per-call execution budget.",
            "severity": "high",
            "category": "engine_limit",
            "field_path": "arguments",
            "evidence": "SQLi analysis exceeded its time budget",
            "recommendation": "Reduce argument size and review the tool input format.",
        }]

    effective_findings = [item for item in findings if not item.get("overridden")]
    risk_score = _risk_score(effective_findings)
    action = "block" if timeout else _action(effective_findings, mode)
    ml_features = sql_ml_features(findings, texts)
    return {
        "detector": "sqli",
        "matched": bool(findings),
        "risk_score": risk_score,
        "rule_risk_score": risk_score,
        "action": action,
        "sql_mode": mode,
        "decision_source": "rule" if findings else "none",
        "findings": findings,
        "ml_features": ml_features,
    }


def get_runtime_configuration() -> dict[str, dict[str, Any]]:
    """Load persisted indicator and tool-mode overrides; defaults remain in the catalog."""
    try:
        from database import SQLiPolicyConfig, SessionLocal
        db = SessionLocal()
        try:
            row = db.query(SQLiPolicyConfig).filter(SQLiPolicyConfig.id == 1).first()
            if row is None:
                return {"indicators": {}, "tool_modes": {}}
            indicators = json.loads(row.indicators_json or "{}")
            tool_modes = json.loads(row.tool_modes_json or "{}")
            return {
                "indicators": indicators if isinstance(indicators, dict) else {},
                "tool_modes": tool_modes if isinstance(tool_modes, dict) else {},
            }
        finally:
            db.close()
    except Exception:
        return {"indicators": {}, "tool_modes": {}}


def get_agent_policy_metadata(agent_id: int) -> dict[str, Any]:
    """Fetch policy-only metadata without changing the authenticated identity contract."""
    from database import MCPAgent, SessionLocal

    db = SessionLocal()
    try:
        row = db.query(MCPAgent.agent_metadata).filter(MCPAgent.id == agent_id).first()
        if row is None:
            return {}
        raw = row[0]
        if not raw:
            return {}
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    finally:
        db.close()