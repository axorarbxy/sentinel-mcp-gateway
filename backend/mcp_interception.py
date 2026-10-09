"""MCP Streamable HTTP interception, forwarding, and event recording."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
import unicodedata
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx
from shared_state import (
    MCP_SESSION_TTL_SECONDS,
    REQUEST_CLAIM_TTL_SECONDS,
    SharedStateUnavailable,
    get_shared_state,
)
from fastapi import Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

logger = logging.getLogger(__name__)

MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 10_485_760
MAX_BATCH_SIZE = 20
MAX_NESTING_DEPTH = 32
MAX_EVENT_PAYLOAD_BYTES = 16_384
MAX_CONCURRENT_PER_AGENT = 20
MAX_CONCURRENT_PER_SESSION = 8
MAX_GLOBAL_UPSTREAM_REQUESTS = 200
EVALUATOR_TIMEOUT_SECONDS = 0.25
UPSTREAM_TIMEOUT_SECONDS = float(os.getenv("SENTINEL_MCP_UPSTREAM_TIMEOUT_SECONDS", "30"))
UPSTREAM_URL = os.getenv("SENTINEL_MCP_UPSTREAM_URL", "").strip()
UPSTREAM_NAME = os.getenv("SENTINEL_MCP_UPSTREAM_NAME", "configured-upstream").strip()
UPSTREAM_TOKEN = os.getenv("SENTINEL_MCP_UPSTREAM_TOKEN", "")
UNKNOWN_METHOD_MODE = os.getenv("SENTINEL_MCP_UNKNOWN_METHOD_MODE", "strict").lower()
SUPPORTED_PROTOCOL_VERSIONS = {"2025-11-25", "2026-07-28"}
_CUSTOM_REDACTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in json.loads(os.getenv("SENTINEL_MCP_REDACTION_PATTERNS", "[]"))
]
ALLOWED_ORIGINS = {
    origin.strip()
    for origin in os.getenv("SENTINEL_CORS_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
}

_SECRET_VALUE_RE = re.compile(
    r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|"
    r"\bcye_(?:live|test)_[A-Za-z0-9_-]+|"
    r"\bsk_sentinel_[A-Za-z0-9_-]+|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
)
_SECRET_FIELD_RE = re.compile(
    r"(?i)(password|passwd|secret|token|credential|api[_-]?key|authorization|private[_-]?key)"
)
_TOOL_NAME_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,255}$")
_KNOWN_METHODS = {
    "initialize",
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/message",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "resources/templates/list",
    "prompts/list",
    "prompts/get",
    "subscriptions/listen",
    "ping",
}
_SERVER_TO_CLIENT_METHODS = {
    "sampling/createMessage",
    "roots/list",
    "elicitation/create",
}

_agent_slots: dict[int, asyncio.Semaphore] = {}
_session_slots: dict[tuple[int, str], asyncio.Semaphore] = {}
_global_upstream_slots = asyncio.Semaphore(MAX_GLOBAL_UPSTREAM_REQUESTS)
_tool_definition_hashes: dict[tuple[str, str], str] = {}
_tool_list_snapshots: dict[str, set[str]] = {}
_pending_tasks: dict[str, asyncio.Task] = {}
_task_request_keys: dict[asyncio.Task, set[str]] = {}


@dataclass
class Decision:
    action: str
    reason: str
    rule_ids: list[str] = field(default_factory=list)


@dataclass
class InterceptionEvent:
    schema_version: str
    event_id: str
    timestamp: str
    session_id: str | None
    request_id: str | None
    agent_id: int
    agent_name: str
    environment: str | None
    direction: str
    method: str
    upstream_server: str
    tool_name: str | None
    arguments: Any
    resource_uri: str | None
    prompt_name: str | None
    decision: str
    decision_reason: str
    matched_rule_ids: list[str]
    latency_ms: float | None
    response_status: str | None
    response_size_bytes: int | None
    source_ip: str | None
    payload_hash: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    sqli_findings: list[dict[str, Any]] = field(default_factory=list)
    rule_risk_score: float = 0.0
    decision_source: str = "rule"


async def default_decision_hook(event: InterceptionEvent, agent: dict[str, Any]) -> Decision:
    """Baseline enforcement only; policy and anomaly evaluators plug in here later."""
    try:
        from ml.inference import score_payload
    except Exception:
        score_payload = None

    allowed_tools = agent.get("allowed_tools") or []
    if event.method == "tools/call" and allowed_tools and event.tool_name not in allowed_tools:
        return Decision("block", "Tool is not in the agent's allowed_tools list", ["BASE-ALLOWED-TOOLS"])
    if event.method in _SERVER_TO_CLIENT_METHODS or event.method.startswith(("sampling/", "roots/", "elicitation/")):
        return Decision("block", "Server-to-client method is invalid in an agent request", ["BASE-METHOD-DIRECTION"])
    if event.method not in _KNOWN_METHODS and UNKNOWN_METHOD_MODE == "strict":
        return Decision("block", "Unknown MCP method blocked in strict mode", ["BASE-UNKNOWN-METHOD"])
    if UNKNOWN_METHOD_MODE not in {"strict", "permissive"}:
        return Decision("block", "Unknown-method mode is invalid", ["BASE-CONFIG-ERROR"])

    sqli_result = None
    path_blocked = False
    if event.method == "tools/call" and event.arguments is not None:
        try:
            from policies import check_path_traversal
            from sqli_policy import analyze_sql_injection, get_agent_policy_metadata, get_runtime_configuration

            path_result = check_path_traversal({"params": {"arguments": event.arguments}})
            path_blocked = not path_result.allowed
            runtime = get_runtime_configuration()
            policy_agent = agent
            if "metadata" not in agent:
                policy_metadata = get_agent_policy_metadata(int(agent["agent_id"]))
                policy_agent = {**agent, "metadata": policy_metadata}
            indicator_config = runtime.get("indicators", {})
            enabled_overrides = {
                key: value["enabled"]
                for key, value in indicator_config.items()
                if isinstance(value, dict) and isinstance(value.get("enabled"), bool)
            }
            severity_overrides = {
                key: value["severity"]
                for key, value in indicator_config.items()
                if isinstance(value, dict) and value.get("severity") in {"low", "medium", "high"}
            }
            sqli_result = analyze_sql_injection(
                event.arguments,
                tool_name=event.tool_name,
                agent=policy_agent,
                enabled_overrides=enabled_overrides,
                severity_overrides=severity_overrides,
                tool_modes=runtime.get("tool_modes", {}),
            )
        except Exception:
            logger.exception("SQLi policy engine failed event_id=%s", event.event_id)
            event.decision_source = "rule"
            return Decision("block", "SQLi policy engine failed; failing closed", ["SQLI-ENGINE-ERROR"])

        event.sqli_findings = sqli_result["findings"]
        event.rule_risk_score = sqli_result["rule_risk_score"]
        event.payload["sqli_analysis"] = sqli_result
        event.payload["sqli_ml_features"] = sqli_result["ml_features"]
        active_findings = [finding for finding in event.sqli_findings if not finding.get("overridden")]
        sqli_rule_ids = list(dict.fromkeys(finding["id"] for finding in active_findings))
        if path_blocked:
            event.decision_source = "rule"
            return Decision("block", "Sensitive path or traversal detected", ["PATH_TRAVERSAL"] + sqli_rule_ids)
        if sqli_result["action"] == "block":
            event.decision_source = "rule"
            return Decision(
                "block",
                "SQL injection indicators blocked by policy: " + ", ".join(sqli_rule_ids[:4]),
                sqli_rule_ids,
            )

    if event.method == "tools/call" and score_payload is not None and event.arguments is not None:
        model_result = score_payload(event.arguments)
        event.payload["ml_score"] = model_result.get("score", 0.0)
        event.payload["ml_label"] = model_result.get("label", 0)
        event.payload["ml_top_signals"] = model_result.get("top_signals", [])
        rule_findings_present = bool(sqli_result and sqli_result["matched"])
        model_present = not model_result.get("fallback", False)
        source = "rule+model" if rule_findings_present and model_present else "rule" if rule_findings_present else "model" if model_present else "rule"
        event.decision_source = source
        event.payload["decision_source"] = source
        if model_result.get("decision") == "BLOCK":
            return Decision("block", "ML payload classifier flagged a malicious tool argument", ["MODEL-PAYLOAD-BLOCK"])
        if model_result.get("decision") == "WARN":
            return Decision("flag", "ML payload classifier marked the tool payload as suspicious", ["MODEL-PAYLOAD-WARN"])

    if sqli_result and sqli_result["action"] == "flag":
        active_findings = [finding for finding in event.sqli_findings if not finding.get("overridden")]
        rule_ids = list(dict.fromkeys(finding["id"] for finding in active_findings))
        if event.decision_source == "rule":
            event.decision_source = "rule"
        return Decision("flag", "SQL injection indicators require review: " + ", ".join(rule_ids[:4]), rule_ids)

    return Decision("allow", "Passed baseline gateway checks")


decision_hook: Callable[[InterceptionEvent, dict[str, Any]], Awaitable[Decision]] = default_decision_hook


class DuplicateJSONKey(ValueError):
    pass


class PayloadLimitExceeded(ValueError):
    pass


class InvalidJSONRPC(ValueError):
    pass


class JSONParseError(InvalidJSONRPC):
    pass


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey("duplicate object key")
        result[key] = value
    return result


def _normalize(value: Any, depth: int = 0) -> Any:
    if depth > MAX_NESTING_DEPTH:
        raise PayloadLimitExceeded("JSON nesting limit exceeded")
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise InvalidJSONRPC("invalid Unicode string") from exc
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize(item, depth + 1) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = _normalize(key, depth + 1)
            if normalized_key in result:
                raise DuplicateJSONKey("keys collide after Unicode normalization")
            result[normalized_key] = _normalize(item, depth + 1)
        return result
    return value


def _parse_body(raw: bytes) -> Any:
    try:
        decoded = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise JSONParseError("Parse error") from exc
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid JSON number")),
        )
    except DuplicateJSONKey as exc:
        raise InvalidJSONRPC("Duplicate JSON object key") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise JSONParseError("Parse error") from exc
    try:
        return _normalize(parsed)
    except DuplicateJSONKey as exc:
        raise InvalidJSONRPC("Object keys collide after Unicode normalization") from exc


def _validate_message(message: Any) -> dict[str, Any]:
    if not isinstance(message, dict):
        raise InvalidJSONRPC("Each JSON-RPC message must be an object")
    if message.get("jsonrpc") != "2.0":
        raise InvalidJSONRPC("jsonrpc must be '2.0'")
    method = message.get("method")
    if not isinstance(method, str) or not method or len(method) > 255:
        raise InvalidJSONRPC("method must be a non-empty string")
    if "params" in message and not isinstance(message["params"], (dict, list)):
        raise InvalidJSONRPC("params must be an object or array")
    if "id" in message:
        request_id = message["id"]
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            raise InvalidJSONRPC("id must be a string or integer")
        if isinstance(request_id, str) and (not request_id or len(request_id) > 255):
            raise InvalidJSONRPC("id string must contain 1 to 255 characters")
    return message


def _validate_batch_ids(messages: list[dict[str, Any]]) -> None:
    request_ids = [json.dumps(message["id"], ensure_ascii=False) for message in messages if "id" in message]
    if len(request_ids) != len(set(request_ids)):
        raise InvalidJSONRPC("Batch request ids must be unique")


def _body_protocol_version(message: dict[str, Any]) -> str | None:
    metadata = message.get("_meta")
    if isinstance(metadata, dict):
        namespace = metadata.get("io.modelcontextprotocol")
        if isinstance(namespace, dict) and isinstance(namespace.get("protocolVersion"), str):
            return namespace["protocolVersion"]
        value = metadata.get("io.modelcontextprotocol/protocolVersion")
        if isinstance(value, str):
            return value
    params = message.get("params")
    if message.get("method") == "initialize" and isinstance(params, dict):
        value = params.get("protocolVersion")
        if isinstance(value, str):
            return value
    return None


def _validate_protocol_version(request: Request, messages: list[dict[str, Any]]) -> str:
    version_headers = request.headers.getlist("mcp-protocol-version")
    if len(version_headers) > 1:
        raise InvalidJSONRPC("HeaderMismatch: multiple protocol version headers")
    header_version = version_headers[0] if version_headers else None
    body_versions = {
        version for message in messages
        if (version := _body_protocol_version(message)) is not None
    }
    if len(body_versions) > 1:
        raise InvalidJSONRPC("HeaderMismatch: different protocol versions in batch")
    body_version = next(iter(body_versions), None)
    if header_version and body_version and header_version != body_version:
        raise InvalidJSONRPC("HeaderMismatch: protocol version header does not match request metadata")
    version = header_version or body_version or "2025-11-25"
    if version not in SUPPORTED_PROTOCOL_VERSIONS:
        raise InvalidJSONRPC("UnsupportedProtocolVersion")
    if version == "2026-07-28" and any(_body_protocol_version(message) is None for message in messages):
        raise InvalidJSONRPC("HeaderMismatch: protocol version metadata is required")
    return version


def _validate_upstream_response(payload: Any, expected_id: Any) -> None:
    if (
        not isinstance(payload, dict)
        or payload.get("jsonrpc") != "2.0"
        or payload.get("id") != expected_id
        or ("result" in payload) == ("error" in payload)
    ):
        raise InvalidJSONRPC("Upstream returned an invalid JSON-RPC response")
    if "result" in payload and not isinstance(payload["result"], dict):
        raise InvalidJSONRPC("Upstream result must be an object")
    if "error" in payload:
        error = payload["error"]
        if (
            not isinstance(error, dict)
            or isinstance(error.get("code"), bool)
            or not isinstance(error.get("code"), int)
            or not isinstance(error.get("message"), str)
        ):
            raise InvalidJSONRPC("Upstream returned an invalid JSON-RPC error")


def _error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _error_http(status_code: int, message: str, request_id: Any = None) -> JSONResponse:
    code = -32002 if status_code == 413 or status_code >= 500 else -32600
    return JSONResponse(
        status_code=status_code,
        content=_error_response(request_id, code, message),
    )


def _safe_request_id(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return None
    request_id = payload.get("id")
    if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
        return None
    return request_id


def _redact(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            field_name: (
                "[REDACTED]"
                if _SECRET_FIELD_RE.search(field_name)
                else _redact(field_value, field_name)
            )
            for field_name, field_value in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, key) for item in value]
    if isinstance(value, str):
        redacted = _SECRET_VALUE_RE.sub(lambda match: f"{match.group(1) or ''}[REDACTED]", value)
        for pattern in _CUSTOM_REDACTION_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        return redacted
    return value


def _payload_for_event(payload: dict[str, Any]) -> tuple[str, str]:
    original = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload_hash = hashlib.sha256(original.encode("utf-8")).hexdigest()
    redacted = json.dumps(_redact(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(redacted.encode("utf-8")) > MAX_EVENT_PAYLOAD_BYTES:
        redacted = json.dumps({
            "truncated": True,
            "sha256": payload_hash,
            "preview": redacted.encode("utf-8")[:MAX_EVENT_PAYLOAD_BYTES // 2].decode("utf-8", "ignore"),
        }, ensure_ascii=False)
    return payload_hash, redacted


def _method_details(message: dict[str, Any]) -> tuple[str | None, Any, str | None, str | None]:
    params = message.get("params", {})
    if not isinstance(params, dict):
        params = {}
    method = message["method"]
    tool_name = params.get("name") if method == "tools/call" else None
    if tool_name is not None:
        if not isinstance(tool_name, str) or not _TOOL_NAME_RE.fullmatch(tool_name):
            raise InvalidJSONRPC("tool name is malformed")
    arguments = params.get("arguments") if method == "tools/call" else None
    resource_uri = params.get("uri") if method == "resources/read" else None
    prompt_name = params.get("name") if method == "prompts/get" else None
    if method == "tools/call":
        if not isinstance(params, dict) or not isinstance(tool_name, str):
            raise InvalidJSONRPC("tools/call requires a tool name")
        if arguments is not None and not isinstance(arguments, dict):
            raise InvalidJSONRPC("tools/call arguments must be an object")
    if method == "resources/read" and not isinstance(resource_uri, str):
        raise InvalidJSONRPC("resources/read requires a URI")
    if method == "prompts/get" and not isinstance(prompt_name, str):
        raise InvalidJSONRPC("prompts/get requires a prompt name")
    return tool_name, arguments, resource_uri, prompt_name


def _new_event(message: dict[str, Any], agent: dict[str, Any], session_id: str | None, source_ip: str | None) -> InterceptionEvent:
    tool_name, arguments, resource_uri, prompt_name = _method_details(message)
    request_id = message.get("id")
    return InterceptionEvent(
        schema_version="1.0",
        event_id=f"evt_{uuid.uuid4().hex}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        session_id=session_id,
        request_id=json.dumps(request_id, ensure_ascii=False) if "id" in message else None,
        agent_id=int(agent["agent_id"]),
        agent_name=str(agent["name"]),
        environment=agent.get("environment"),
        direction="agent_to_server",
        method=message["method"],
        upstream_server=UPSTREAM_NAME,
        tool_name=tool_name,
        arguments=arguments,
        resource_uri=resource_uri,
        prompt_name=prompt_name,
        decision="allow",
        decision_reason="",
        matched_rule_ids=[],
        latency_ms=None,
        response_status=None,
        response_size_bytes=None,
        source_ip=source_ip,
    )


async def _evaluate(event: InterceptionEvent, agent: dict[str, Any]) -> Decision:
    try:
        decision = await asyncio.wait_for(decision_hook(event, agent), timeout=EVALUATOR_TIMEOUT_SECONDS)
        if decision.action not in {"allow", "block", "flag"}:
            raise ValueError("decision hook returned an unsupported action")
        return decision
    except asyncio.TimeoutError:
        logger.error("MCP decision hook timed out event_id=%s", event.event_id)
        return Decision("block", "Decision hook timed out", ["GATEWAY-EVALUATOR-TIMEOUT"])
    except Exception:
        logger.error("MCP decision hook failed event_id=%s", event.event_id)
        return Decision("block", "Decision hook failed", ["GATEWAY-EVALUATOR-ERROR"])


def _agent_semaphore(agent_id: int) -> asyncio.Semaphore:
    if agent_id not in _agent_slots:
        _agent_slots[agent_id] = asyncio.Semaphore(MAX_CONCURRENT_PER_AGENT)
    return _agent_slots[agent_id]


def _session_semaphore(agent_id: int, session_id: str | None) -> asyncio.Semaphore:
    key = (agent_id, session_id or "")
    if key not in _session_slots:
        _session_slots[key] = asyncio.Semaphore(MAX_CONCURRENT_PER_SESSION)
    return _session_slots[key]


def request_claim_key(agent_id: int, session_id: str | None, request_id: Any) -> str:
    return f"{agent_id}:{session_id or ''}:{json.dumps(request_id, ensure_ascii=False, separators=(',', ':'))}"


def _set_local_request_owner(request_keys: list[str], task: asyncio.Task) -> None:
    owned = _task_request_keys.setdefault(task, set())
    for key in request_keys:
        _pending_tasks[key] = task
        owned.add(key)


def _transfer_local_request_owner(request_keys: list[str], task: asyncio.Task) -> None:
    for key in request_keys:
        previous = _pending_tasks.get(key)
        if previous is not None and previous in _task_request_keys:
            _task_request_keys[previous].discard(key)
            if not _task_request_keys[previous]:
                _task_request_keys.pop(previous, None)
    _set_local_request_owner(request_keys, task)


def cancel_local_request(request_key: str) -> None:
    task = _pending_tasks.get(request_key)
    if task and task is not asyncio.current_task():
        task.cancel()


async def _claim_pending_requests(messages: list[dict[str, Any]], agent_id: int, session_id: str | None) -> list[str] | None:
    keys = [
        request_claim_key(agent_id, session_id, message["id"])
        for message in messages if "id" in message
    ]
    if not keys:
        return []
    state = get_shared_state()
    try:
        claimed = await state.claim_requests(keys, state.worker_id, REQUEST_CLAIM_TTL_SECONDS)
    except SharedStateUnavailable:
        raise
    if not claimed:
        return None
    return keys


async def _release_pending_requests(request_keys: list[str]) -> None:
    if not request_keys:
        return
    state = get_shared_state()
    try:
        await state.release_requests(request_keys, state.worker_id)
    except SharedStateUnavailable:
        logger.exception("Failed to release shared MCP request claims; leases will expire")
    for key in request_keys:
        task = _pending_tasks.pop(key, None)
        if task is not None and task in _task_request_keys:
            _task_request_keys[task].discard(key)
            if not _task_request_keys[task]:
                _task_request_keys.pop(task, None)


def _start_claim_renewer(request_keys: list[str], task: asyncio.Task | None) -> tuple[asyncio.Event, asyncio.Task | None]:
    stop = asyncio.Event()
    if not request_keys or task is None:
        return stop, None
    return stop, asyncio.create_task(_renew_pending_requests(request_keys, stop, task))


async def _stop_claim_renewer(stop: asyncio.Event, renewer: asyncio.Task | None) -> None:
    stop.set()
    if renewer is not None:
        renewer.cancel()
        try:
            await renewer
        except asyncio.CancelledError:
            pass


async def _renew_pending_requests(request_keys: list[str], stop: asyncio.Event, stream_task: asyncio.Task) -> None:
    state = get_shared_state()
    delay = max(5, REQUEST_CLAIM_TTL_SECONDS // 3)
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
            return
        except asyncio.TimeoutError:
            pass
        try:
            renewed = await state.renew_requests(request_keys, state.worker_id, REQUEST_CLAIM_TTL_SECONDS)
        except SharedStateUnavailable:
            logger.exception("Failed to renew shared MCP request claims")
            stream_task.cancel()
            return
        if not renewed:
            logger.error("Shared MCP request claim expired or was replaced")
            stream_task.cancel()
            return


def _validate_upstream() -> tuple[str, str]:
    if not UPSTREAM_URL:
        raise ValueError("No MCP upstream is configured")
    parsed = urlsplit(UPSTREAM_URL)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Configured MCP upstream URL is invalid")
    return UPSTREAM_URL, UPSTREAM_NAME or "configured-upstream"


async def _persist_and_emit(event: InterceptionEvent, emit_event: Callable[[dict[str, Any]], Awaitable[None]] | None) -> None:
    event_payload = _redact(asdict(event))
    payload_hash, payload_json = _payload_for_event({
        "arguments": event.arguments,
        **event.payload,
    })
    if "ml_score" in event.payload:
        event_payload["ml_score"] = event.payload.get("ml_score")
        event_payload["ml_label"] = event.payload.get("ml_label")
        event_payload["ml_top_signals"] = event.payload.get("ml_top_signals", [])
        event_payload["decision_source"] = event.payload.get("decision_source", "rule")
    event_payload["payload_hash"] = event.payload_hash or payload_hash
    if event.payload_hash is None:
        event.payload_hash = payload_hash
    event_payload["payload"] = json.loads(payload_json)
    event_payload["sqli_findings"] = _redact(event.sqli_findings)
    event_payload["rule_risk_score"] = event.rule_risk_score
    event_payload["decision_source"] = event.decision_source
    try:
        from database import MCPRequestEvent, SessionLocal

        db = SessionLocal()
        try:
            db.add(MCPRequestEvent(
                event_id=event.event_id,
                schema_version=event.schema_version,
                timestamp=datetime.fromisoformat(event.timestamp.replace("Z", "+00:00")).replace(tzinfo=None),
                session_id=_redact(event.session_id),
                request_id=_redact(event.request_id),
                agent_id=event.agent_id,
                agent_name=_redact(event.agent_name),
                environment=event.environment,
                direction=event.direction,
                method=_redact(event.method),
                upstream_server=event.upstream_server,
                tool_name=_redact(event.tool_name),
                resource_uri=_redact(event.resource_uri),
                prompt_name=_redact(event.prompt_name),
                decision=event.decision,
                decision_reason=_redact(event.decision_reason[:1000]),
                matched_rule_ids=json.dumps(_redact(event.matched_rule_ids)),
                latency_ms=event.latency_ms,
                response_status=event.response_status,
                response_size_bytes=event.response_size_bytes,
                source_ip=event.source_ip,
                payload_hash=event.payload_hash or payload_hash,
                payload_json=payload_json,
                sqli_findings_json=json.dumps(_redact(event.sqli_findings), ensure_ascii=False),
                rule_risk_score=event.rule_risk_score,
                decision_source=event.decision_source,
            ))
            from database import MCPAgent

            agent_record = db.query(MCPAgent).filter(MCPAgent.id == event.agent_id).first()
            if agent_record is not None:
                agent_record.total_requests = (agent_record.total_requests or 0) + 1
                if event.decision == "block":
                    agent_record.blocked_requests = (agent_record.blocked_requests or 0) + 1
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.error("Failed to persist MCP event event_id=%s", event.event_id)
    if emit_event:
        try:
            await emit_event(event_payload)
        except Exception:
            logger.error("Failed to emit MCP event event_id=%s", event.event_id)


def _upstream_headers(request: Request, session_id: str | None) -> dict[str, str]:
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
    }
    protocol_version = getattr(
        request.state,
        "mcp_protocol_version",
        request.headers.get("mcp-protocol-version"),
    )
    if protocol_version:
        headers["mcp-protocol-version"] = protocol_version
    if session_id:
        headers["mcp-session-id"] = session_id
    if UPSTREAM_TOKEN:
        headers["authorization"] = f"Bearer {UPSTREAM_TOKEN}"
    return headers


def _accepts_mcp_response(value: str) -> bool:
    accepted = {
        item.split(";", 1)[0].strip().lower()
        for item in value.split(",")
    }
    accepts_json = bool(accepted & {"*/*", "application/*", "application/json"})
    accepts_sse = bool(accepted & {"*/*", "text/*", "text/event-stream"})
    return accepts_json and accepts_sse


def _response_headers(upstream: httpx.Response) -> dict[str, str]:
    allowed = {"content-type", "cache-control", "mcp-session-id", "mcp-protocol-version", "last-event-id"}
    headers = {key: value for key, value in upstream.headers.items() if key.lower() in allowed}
    if headers.get("content-type", "").lower().startswith("text/event-stream"):
        headers["X-Accel-Buffering"] = "no"
    return headers


def _tools_list_result(
    response_message: dict[str, Any],
    agent: dict[str, Any],
    session_id: str | None,
) -> tuple[dict[str, Any], bool]:
    if "result" not in response_message or not isinstance(response_message["result"], dict):
        return response_message, False
    tools = response_message["result"].get("tools")
    if not isinstance(tools, list):
        return response_message, False
    allowed_tools = agent.get("allowed_tools") or []
    valid_tools = [tool for tool in tools if isinstance(tool, dict) and isinstance(tool.get("name"), str)]
    changed = False
    current_names: set[str] = set()
    for tool in valid_tools:
        tool_name = tool["name"]
        current_names.add(tool_name)
        definition = json.dumps(
            {key: tool.get(key) for key in ("name", "description", "inputSchema")},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        current_hash = hashlib.sha256(definition.encode("utf-8")).hexdigest()
        identity_key = (UPSTREAM_NAME, tool_name)
        previous = _tool_definition_hashes.get(identity_key)
        if previous is not None and previous != current_hash:
            changed = True
        _tool_definition_hashes[identity_key] = current_hash
    if not response_message["result"].get("nextCursor"):
        previous_names = _tool_list_snapshots.get(UPSTREAM_NAME)
        if previous_names is not None and previous_names - current_names:
            changed = True
        _tool_list_snapshots[UPSTREAM_NAME] = current_names
    filtered = valid_tools
    if allowed_tools:
        filtered = [tool for tool in valid_tools if tool["name"] in allowed_tools]
    response_message = dict(response_message)
    response_message["result"] = dict(response_message["result"])
    response_message["result"]["tools"] = filtered
    return response_message, changed


def _transform_response(
    response_payload: Any,
    messages: list[dict[str, Any]],
    agent: dict[str, Any],
    session_id: str | None,
) -> tuple[Any, set[str]]:
    changed_definitions: set[str] = set()
    methods_by_id = {
        json.dumps(message["id"], ensure_ascii=False): message["method"]
        for message in messages
        if "id" in message
    }
    if isinstance(response_payload, list):
        transformed = []
        for item in response_payload:
            if isinstance(item, dict) and methods_by_id.get(json.dumps(item.get("id"), ensure_ascii=False)) == "tools/list":
                item, changed = _tools_list_result(item, agent, session_id)
                if changed:
                    changed_definitions.add("TOOL-DEFINITION-CHANGED")
            transformed.append(item)
        return transformed, changed_definitions
    if (
        isinstance(response_payload, dict)
        and methods_by_id.get(json.dumps(response_payload.get("id"), ensure_ascii=False)) == "tools/list"
    ):
        response_payload, changed = _tools_list_result(response_payload, agent, session_id)
        if changed:
            changed_definitions.add("TOOL-DEFINITION-CHANGED")
    return response_payload, changed_definitions


def _mark_response_events(
    events: list[InterceptionEvent],
    response_payload: Any,
    size: int,
    elapsed_ms: float,
) -> None:
    responses = response_payload if isinstance(response_payload, list) else [response_payload]
    by_id = {
        json.dumps(item.get("id"), ensure_ascii=False): item
        for item in responses if isinstance(item, dict) and "id" in item
    }
    for event in events:
        event.latency_ms = elapsed_ms
        response = by_id.get(event.request_id) if event.request_id is not None else None
        if response is None:
            event.response_status = "success"
        else:
            event.response_status = "error" if "error" in response else "success"
            event.payload["response"] = response.get("result", response.get("error"))
        event.response_size_bytes = size


async def _read_limited(response: httpx.Response, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    chunks = bytearray()
    async for chunk in response.aiter_bytes():
        chunks.extend(chunk)
        if len(chunks) > limit:
            raise PayloadLimitExceeded("upstream response size limit exceeded")
    return bytes(chunks)


def _sse_frame_transform(
    frame: bytes,
    messages: list[dict[str, Any]],
    agent: dict[str, Any],
    session_id: str | None,
) -> tuple[bytes, Any | None, bool]:
    try:
        text = frame.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return frame, None, False
    data_lines = []
    other_lines = []
    for line in text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
        else:
            other_lines.append(line)
    if not data_lines:
        return frame, None, False
    try:
        payload = _parse_body("\n".join(data_lines).encode("utf-8"))
    except InvalidJSONRPC as exc:
        raise InvalidJSONRPC("Upstream emitted malformed SSE JSON") from exc
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        raise InvalidJSONRPC("Upstream emitted a non-JSON-RPC SSE message")
    if "method" in payload:
        if not isinstance(payload["method"], str) or "result" in payload or "error" in payload:
            raise InvalidJSONRPC("Upstream emitted an invalid SSE notification/request")
    else:
        _validate_upstream_response(payload, messages[0].get("id"))
    transformed, changed_set = _transform_response(payload, messages, agent, session_id)
    output = [line for line in other_lines if line]
    output.append("data: " + json.dumps(transformed, ensure_ascii=False, separators=(",", ":")))
    return ("\n".join(output) + "\n\n").encode("utf-8"), transformed, bool(changed_set)


def _record_server_to_client_attempt(event: InterceptionEvent, payload: Any) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("method"), str):
        return
    method = payload["method"]
    if not method.startswith(("sampling/", "roots/", "elicitation/")):
        return
    event.direction = "server_to_agent"
    event.decision = "flag"
    event.decision_reason = "Upstream initiated a server-to-client interaction"
    if "SERVER-TO-CLIENT-REQUEST" not in event.matched_rule_ids:
        event.matched_rule_ids.append("SERVER-TO-CLIENT-REQUEST")
    event.payload.setdefault("server_messages", []).append(payload)


async def _stream_sse(
    upstream: httpx.Response,
    client: httpx.AsyncClient,
    events: list[InterceptionEvent],
    messages: list[dict[str, Any]],
    agent: dict[str, Any],
    session_id: str | None,
    started: float,
    emit_event: Callable[[dict[str, Any]], Awaitable[None]] | None,
    pending_keys: list[str],
    claim_stop: asyncio.Event,
    claim_renewer: asyncio.Task | None,
):
    await _stop_claim_renewer(claim_stop, claim_renewer)
    stream_task = asyncio.current_task()
    if stream_task is not None and pending_keys:
        _transfer_local_request_owner(pending_keys, stream_task)
        claim_stop, claim_renewer = _start_claim_renewer(pending_keys, stream_task)
    frame_lines: list[str] = []
    total_bytes = 0
    final_message = None
    try:
        async with (
            _agent_semaphore(int(agent["agent_id"])),
            _session_semaphore(int(agent["agent_id"]), session_id),
            _global_upstream_slots,
        ):
            async for line in upstream.aiter_lines():
                total_bytes += len(line.encode("utf-8")) + 1
                if total_bytes > MAX_RESPONSE_BYTES:
                    raise PayloadLimitExceeded("upstream response size limit exceeded")
                frame_lines.append(line)
                if line != "":
                    continue
                frame = ("\n".join(frame_lines) + "\n").encode("utf-8")
                frame_lines.clear()
                transformed, parsed, changed = _sse_frame_transform(frame, messages, agent, session_id)
                if parsed is not None:
                    final_message = parsed
                    for event in events:
                        _record_server_to_client_attempt(event, parsed)
                if changed:
                    for event in events:
                        event.decision = "flag"
                        event.decision_reason = "A known tool definition changed"
                        event.matched_rule_ids.append("TOOL-DEFINITION-CHANGED")
                yield transformed
            if frame_lines:
                transformed, parsed, changed = _sse_frame_transform(
                    ("\n".join(frame_lines)).encode("utf-8"), messages, agent, session_id
                )
                if parsed is not None:
                    final_message = parsed
                    for event in events:
                        _record_server_to_client_attempt(event, parsed)
                if changed:
                    for event in events:
                        event.decision = "flag"
                        event.decision_reason = "A known tool definition changed"
                        event.matched_rule_ids.append("TOOL-DEFINITION-CHANGED")
                yield transformed
            _mark_response_events(events, final_message, total_bytes, (time.perf_counter() - started) * 1000)
    except asyncio.CancelledError:
        for event in events:
            event.response_status = "error"
            event.decision_reason = "Agent disconnected before the upstream response completed"
        raise
    except Exception as exc:
        for event in events:
            event.response_status = "error"
            event.decision_reason = event.decision_reason or "Upstream stream failed"
        logger.error("MCP upstream stream failed upstream=%s error_type=%s", UPSTREAM_NAME, type(exc).__name__)
    finally:
        await upstream.aclose()
        await client.aclose()
        await _stop_claim_renewer(claim_stop, claim_renewer)
        await _release_pending_requests(pending_keys)
        for event in events:
            await _persist_and_emit(event, emit_event)


async def _forward(
    request: Request,
    messages: list[dict[str, Any]],
    allowed: list[tuple[dict[str, Any], InterceptionEvent]],
    blocked: list[tuple[dict[str, Any], InterceptionEvent]],
    agent: dict[str, Any],
    session_id: str | None,
    emit_event: Callable[[dict[str, Any]], Awaitable[None]] | None,
    is_batch: bool,
) -> Response:
    sent_messages = [message for message, _ in allowed]
    sent_payload: Any = sent_messages[0] if len(sent_messages) == 1 else sent_messages
    if len(sent_messages) == 0:
        for _, event in blocked:
            event.response_status = "error"
            event.latency_ms = 0.0
            await _persist_and_emit(event, emit_event)
        blocked_replies = [
            _error_response(message.get("id"), -32000, event.decision_reason)
            for message, event in blocked if "id" in message
        ]
        if not blocked_replies:
            return Response(status_code=202)
        return JSONResponse(blocked_replies[0] if len(blocked_replies) == 1 else blocked_replies)

    agent_id = int(agent["agent_id"])
    upstream_url, _ = _validate_upstream()
    try:
        claimed_keys = await _claim_pending_requests(sent_messages, agent_id, session_id)
    except SharedStateUnavailable:
        logger.exception("Shared state unavailable while claiming MCP request IDs")
        for _, event in allowed:
            event.decision = "block"
            event.decision_reason = "Shared request coordination is unavailable"
            event.response_status = "error"
            await _persist_and_emit(event, emit_event)
        return _error_http(503, "MCP request coordination unavailable")
    if claimed_keys is None:
        for _, event in allowed:
            event.decision = "block"
            event.decision_reason = "Duplicate in-flight JSON-RPC request id"
            event.matched_rule_ids.append("GATEWAY-DUPLICATE-REQUEST-ID")
            event.response_status = "error"
            await _persist_and_emit(event, emit_event)
        for _, event in blocked:
            event.response_status = "error"
            await _persist_and_emit(event, emit_event)
        return _error_http(400, "Duplicate in-flight JSON-RPC request id")

    claim_task = asyncio.current_task()
    claim_stop, claim_renewer = _start_claim_renewer(claimed_keys, claim_task)
    started = time.perf_counter()
    outgoing_headers = _upstream_headers(request, session_id)
    async with _agent_semaphore(int(agent["agent_id"])):
        async with _session_semaphore(int(agent["agent_id"]), session_id):
            if len(sent_messages) == 1 and not is_batch:
                message, event = allowed[0]
                keep_pending = False
                client = httpx.AsyncClient(timeout=httpx.Timeout(UPSTREAM_TIMEOUT_SECONDS, read=None))
                await _global_upstream_slots.acquire()
                try:
                    upstream_request = client.build_request(
                        "POST",
                        upstream_url,
                        headers=outgoing_headers,
                        content=json.dumps(sent_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                    )
                    upstream = await client.send(upstream_request, stream=True)
                    if upstream.status_code >= 400:
                        body = await asyncio.wait_for(_read_limited(upstream), timeout=UPSTREAM_TIMEOUT_SECONDS)
                        event.response_status = "error"
                        event.response_size_bytes = len(body)
                        event.latency_ms = (time.perf_counter() - started) * 1000
                        event.payload["upstream_error_status"] = upstream.status_code
                        await upstream.aclose()
                        await client.aclose()
                        await _persist_and_emit(event, emit_event)
                        return _error_http(502, "MCP upstream rejected the request", message.get("id"))
                    if "id" not in message and upstream.status_code == 202:
                        event.response_status = "success"
                        event.latency_ms = (time.perf_counter() - started) * 1000
                        await upstream.aclose()
                        await client.aclose()
                        await _persist_and_emit(event, emit_event)
                        return Response(status_code=202, headers=_response_headers(upstream))
                    returned_session = upstream.headers.get("mcp-session-id")
                    if returned_session:
                        try:
                            session_bound = len(returned_session) <= 255 and await get_shared_state().bind_mcp_session(
                                returned_session, int(agent["agent_id"]), MCP_SESSION_TTL_SECONDS,
                            )
                        except SharedStateUnavailable:
                            logger.exception("Shared state unavailable while binding MCP session")
                            await upstream.aclose()
                            await client.aclose()
                            event.response_status = "error"
                            event.decision_reason = "Shared session ownership is unavailable"
                            await _persist_and_emit(event, emit_event)
                            return _error_http(503, "MCP session coordination unavailable", message.get("id"))
                        if not session_bound:
                            await upstream.aclose()
                            await client.aclose()
                            event.response_status = "error"
                            event.decision_reason = "Upstream session identifier collision or invalid length"
                            await _persist_and_emit(event, emit_event)
                            return _error_http(502, "MCP upstream session error", message.get("id"))
                    content_type = upstream.headers.get("content-type", "").lower()
                    if content_type.startswith("text/event-stream"):
                        keep_pending = bool(claimed_keys)
                        return StreamingResponse(
                            _stream_sse(
                                upstream, client, [event], [message], agent,
                                returned_session or session_id, started, emit_event,
                                claimed_keys, claim_stop, claim_renewer,
                            ),
                            status_code=upstream.status_code,
                            headers=_response_headers(upstream),
                            media_type="text/event-stream",
                        )
                    if not content_type.startswith("application/json"):
                        await upstream.aclose()
                        await client.aclose()
                        event.response_status = "error"
                        event.decision_reason = "Unsupported upstream content type"
                        await _persist_and_emit(event, emit_event)
                        return _error_http(502, "MCP upstream returned an unsupported content type", message.get("id"))
                    raw_response = await asyncio.wait_for(_read_limited(upstream), timeout=UPSTREAM_TIMEOUT_SECONDS)
                    response_payload = _parse_body(raw_response)
                    _validate_upstream_response(response_payload, message.get("id"))
                    transformed, changed_set = _transform_response(response_payload, [message], agent, session_id)
                    if changed_set:
                        event.decision = "flag"
                        event.decision_reason = "A known tool definition changed"
                        event.matched_rule_ids.extend(sorted(changed_set))
                    _mark_response_events([event], transformed, len(raw_response), (time.perf_counter() - started) * 1000)
                    event.payload["request"] = message
                    await upstream.aclose()
                    await client.aclose()
                    await _persist_and_emit(event, emit_event)
                    body = json.dumps(transformed, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    return Response(
                        content=body,
                        status_code=upstream.status_code,
                        headers=_response_headers(upstream),
                        media_type="application/json",
                    )
                except asyncio.CancelledError:
                    raise
                except (httpx.HTTPError, PayloadLimitExceeded, InvalidJSONRPC, ValueError, TimeoutError):
                    logger.error("MCP upstream request failed upstream=%s", UPSTREAM_NAME)
                    event.response_status = "error"
                    event.latency_ms = (time.perf_counter() - started) * 1000
                    event.decision_reason = "MCP upstream unavailable or returned invalid data"
                    await _persist_and_emit(event, emit_event)
                    await client.aclose()
                    return _error_http(502, "MCP upstream unavailable or returned invalid data", message.get("id"))
                finally:
                    _global_upstream_slots.release()
                    if not keep_pending:
                        await _stop_claim_renewer(claim_stop, claim_renewer)
                        await _release_pending_requests(claimed_keys)
            else:
                batch_task = asyncio.current_task()
                if batch_task is not None and claimed_keys:
                    _transfer_local_request_owner(claimed_keys, batch_task)
                try:
                    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT_SECONDS) as client:
                        batch_slots = asyncio.Semaphore(MAX_CONCURRENT_PER_SESSION)

                        async def send_one(message: dict[str, Any]) -> Any:
                            async with batch_slots, _global_upstream_slots:
                                response = await client.post(
                                    upstream_url,
                                    headers=outgoing_headers,
                                    content=json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                                )
                            if response.status_code >= 400:
                                raise httpx.HTTPStatusError("upstream rejected batch member", request=response.request, response=response)
                            if response.status_code == 202:
                                    return None, 0
                            if response.headers.get("content-type", "").lower().startswith("text/event-stream"):
                                raise ValueError("SSE responses for batched requests are unsupported")
                            if not response.headers.get("content-type", "").lower().startswith("application/json"):
                                raise ValueError("unsupported upstream content type")
                            raw_response = await _read_limited(response)
                            payload = _parse_body(raw_response)
                            _validate_upstream_response(payload, message.get("id"))
                            return payload, len(raw_response)

                        results = await asyncio.gather(*(send_one(message) for message in sent_messages))
                    forwarded_responses = [response for response, _ in results if response is not None]
                    transformed, changed_set = _transform_response(forwarded_responses, sent_messages, agent, session_id)
                    by_id = {
                        json.dumps(response.get("id"), ensure_ascii=False): response
                        for response in (transformed if isinstance(transformed, list) else [transformed])
                        if isinstance(response, dict) and "id" in response
                    }
                    elapsed = (time.perf_counter() - started) * 1000
                    response_sizes = {
                        json.dumps(response.get("id"), ensure_ascii=False): size
                        for response, size in results
                        if isinstance(response, dict) and "id" in response
                    }
                    for message, event in allowed:
                        response_payload = by_id.get(json.dumps(message.get("id"), ensure_ascii=False))
                        _mark_response_events(
                            [event],
                            response_payload,
                            response_sizes.get(json.dumps(message.get("id"), ensure_ascii=False), 0),
                            elapsed,
                        )
                        event.payload["request"] = message
                        if changed_set:
                            event.decision = "flag"
                            event.decision_reason = "A known tool definition changed"
                            event.matched_rule_ids.extend(sorted(changed_set))
                        await _persist_and_emit(event, emit_event)
                    blocked_replies = [
                        _error_response(message.get("id"), -32000, event.decision_reason)
                        for message, event in blocked if "id" in message
                    ]
                    for _, event in blocked:
                        event.response_status = "error"
                        event.latency_ms = elapsed
                        await _persist_and_emit(event, emit_event)
                    all_replies = blocked_replies + [
                        response for response in (transformed if isinstance(transformed, list) else [transformed])
                        if isinstance(response, dict) and "id" in response
                    ]
                    if not all_replies:
                        return Response(status_code=202)
                    return JSONResponse(all_replies)
                except (httpx.HTTPError, PayloadLimitExceeded, InvalidJSONRPC, ValueError, TimeoutError):
                    logger.error("MCP upstream batch request failed upstream=%s", UPSTREAM_NAME)
                    for _, event in allowed:
                        event.response_status = "error"
                        event.latency_ms = (time.perf_counter() - started) * 1000
                        event.decision_reason = "MCP upstream unavailable or returned invalid data"
                        await _persist_and_emit(event, emit_event)
                    for _, event in blocked:
                        event.response_status = "error"
                        await _persist_and_emit(event, emit_event)
                    return _error_http(502, "MCP upstream unavailable or returned invalid data")
                finally:
                    await _stop_claim_renewer(claim_stop, claim_renewer)
                    await _release_pending_requests(claimed_keys)


async def intercept_request(
    request: Request,
    agent: dict[str, Any],
    emit_event: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
) -> Response:
    """Authenticate upstream routing context, validate JSON-RPC, decide, then forward."""
    content_length = request.headers.get("content-length")
    if content_length and (not content_length.isdigit() or int(content_length) > MAX_REQUEST_BYTES):
        return _error_http(413, "MCP request exceeds the configured size limit")
    origin = request.headers.get("origin")
    if origin and origin not in ALLOWED_ORIGINS:
        return JSONResponse(
            status_code=403,
            content=_error_response(None, -32003, "Origin is not permitted"),
        )
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return _error_http(415, "MCP requests must use application/json")
    if not _accepts_mcp_response(request.headers.get("accept", "*/*")):
        return _error_http(406, "MCP clients must accept JSON and server-sent events")
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > MAX_REQUEST_BYTES:
            return _error_http(413, "MCP request exceeds the configured size limit")
    def invalid_event(reason: str) -> InterceptionEvent:
        event = InterceptionEvent(
            schema_version="1.0",
            event_id=f"evt_{uuid.uuid4().hex}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=request.headers.get("mcp-session-id"),
            request_id=None,
            agent_id=int(agent["agent_id"]),
            agent_name=str(agent["name"]),
            environment=agent.get("environment"),
            direction="agent_to_server",
            method="invalid",
            upstream_server=UPSTREAM_NAME,
            tool_name=None,
            arguments=None,
            resource_uri=None,
            prompt_name=None,
            decision="block",
            decision_reason=reason,
            matched_rule_ids=["GATEWAY-INVALID-REQUEST"],
            latency_ms=None,
            response_status="error",
            response_size_bytes=0,
            source_ip=request.client.host if request.client else None,
            payload_hash=hashlib.sha256(raw).hexdigest(),
            payload={"body_sha256": hashlib.sha256(raw).hexdigest()},
        )
        return event
    payload: Any = None
    try:
        payload = _parse_body(bytes(raw))
        if isinstance(payload, list):
            if not payload or len(payload) > MAX_BATCH_SIZE:
                raise PayloadLimitExceeded("batch size is outside the allowed range")
            messages = [_validate_message(item) for item in payload]
            _validate_batch_ids(messages)
        else:
            messages = [_validate_message(payload)]
    except PayloadLimitExceeded as exc:
        status = 413 if "size" in str(exc) or "nesting" in str(exc) or "batch" in str(exc) else 400
        await _persist_and_emit(invalid_event(str(exc)), emit_event)
        return _error_http(status, str(exc))
    except JSONParseError:
        await _persist_and_emit(invalid_event("Malformed JSON-RPC payload"), emit_event)
        return JSONResponse(status_code=400, content=_error_response(None, -32700, "Parse error"))
    except InvalidJSONRPC as exc:
        await _persist_and_emit(invalid_event("Invalid JSON-RPC request"), emit_event)
        return _error_http(400, str(exc), _safe_request_id(payload))
    try:
        request.state.mcp_protocol_version = _validate_protocol_version(request, messages)
    except InvalidJSONRPC as exc:
        await _persist_and_emit(invalid_event("Invalid MCP protocol version metadata"), emit_event)
        code = -32004 if "UnsupportedProtocolVersion" in str(exc) else -32003
        request_id = None if isinstance(payload, list) else _safe_request_id(payload)
        return JSONResponse(status_code=400, content=_error_response(request_id, code, str(exc)))

    # Streamable HTTP client POSTs carry requests or notifications, never responses.
    session_id = request.headers.get("mcp-session-id")
    agent_id = int(agent["agent_id"])
    if session_id:
        try:
            session_valid = (
                len(session_id) <= 255
                and await get_shared_state().validate_mcp_session(
                    session_id, agent_id, MCP_SESSION_TTL_SECONDS,
                )
            )
        except SharedStateUnavailable:
            logger.exception("Shared state unavailable while validating MCP session")
            return _error_http(503, "MCP session coordination unavailable")
        if not session_valid:
            for message in messages:
                try:
                    event = _new_event(
                        message, agent, session_id, request.client.host if request.client else None,
                    )
                except InvalidJSONRPC:
                    event = invalid_event("Request used an unknown MCP session")
                event.decision = "block"
                event.decision_reason = "MCP session is not bound to this agent"
                event.matched_rule_ids = ["GATEWAY-SESSION-OWNERSHIP"]
                event.response_status = "error"
                await _persist_and_emit(event, emit_event)
            return _error_http(404, "MCP session not found")

    if len(messages) == 1 and messages[0]["method"] == "notifications/cancelled":
        params = messages[0].get("params", {})
        cancelled_id = params.get("requestId") if isinstance(params, dict) else None
        request_key = request_claim_key(agent_id, session_id, cancelled_id)
        state = get_shared_state()
        try:
            owner_worker = await state.get_request_owner(request_key)
            if owner_worker == state.worker_id:
                cancel_local_request(request_key)
            elif owner_worker:
                await state.publish_message({
                    "kind": "cancel",
                    "worker_id": state.worker_id,
                    "request_key": request_key,
                })
        except SharedStateUnavailable:
            logger.exception("Shared state unavailable while routing MCP cancellation")
            return Response(status_code=503)
        event = _new_event(messages[0], agent, session_id, request.client.host if request.client else None)
        event.decision = "allow"
        event.decision_reason = "Request cancellation processed"
        event.response_status = "success"
        event.latency_ms = 0.0
        await _persist_and_emit(event, emit_event)
        return Response(status_code=202)

    allowed: list[tuple[dict[str, Any], InterceptionEvent]] = []
    blocked: list[tuple[dict[str, Any], InterceptionEvent]] = []
    source_ip = request.client.host if request.client else None
    for message in messages:
        started = time.perf_counter()
        try:
            event = _new_event(message, agent, session_id, source_ip)
        except InvalidJSONRPC as exc:
            await _persist_and_emit(invalid_event("Invalid JSON-RPC method parameters"), emit_event)
            return _error_http(400, str(exc), message.get("id"))
        decision = await _evaluate(event, agent)
        event.decision = decision.action
        event.decision_reason = decision.reason
        event.matched_rule_ids = list(decision.rule_ids)
        event.latency_ms = (time.perf_counter() - started) * 1000
        forwarded = {
            key: value for key, value in message.items()
            if key not in {"agent_id", "agent", "identity"}
        }
        event.payload["request"] = forwarded
        if decision.action == "block":
            blocked.append((message, event))
        else:
            # Client-provided identity claims are never forwarded upstream.
            allowed.append((forwarded, event))

    try:
        if allowed:
            _validate_upstream()
    except ValueError:
        for _, event in allowed:
            event.response_status = "error"
            event.decision_reason = "MCP upstream is not configured"
            await _persist_and_emit(event, emit_event)
        for _, event in blocked:
            event.response_status = "error"
            await _persist_and_emit(event, emit_event)
        return _error_http(503, "MCP upstream is not configured")

    return await _forward(
        request, messages, allowed, blocked, agent, session_id, emit_event,
        is_batch=isinstance(payload, list),
    )
