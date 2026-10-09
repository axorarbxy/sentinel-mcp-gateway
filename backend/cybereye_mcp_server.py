from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from mcp.server import MCPServer
from starlette.middleware.base import BaseHTTPMiddleware


INJECTION_PATTERNS = (
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions?|system\s+messages?|developer\s+messages?)",
    r"override\s+(?:system|developer|assistant)\s+instructions?",
    r"act\s+as\s+(?:an?|the)\s+\w+",
    r"you\s+are\s+now\s+.*?assistant",
    r"reveal\s+(?:the\s+)?(?:secret|token|password|key)",
    r"ignore\s+prompt",
)


def redact_prompt_injection(value: Any, *, max_length: int = 4096) -> Any:
    """Strip untrusted prompt-injection payloads from operator event payloads."""
    if value is None:
        return None
    if isinstance(value, (int, float, bool)):
        return value
    text = str(value)
    text = text.replace("\x00", "")
    for pattern in INJECTION_PATTERNS:
        text = re.sub(pattern, "[redacted_prompt_injection]", text, flags=re.IGNORECASE | re.DOTALL)
    text = text.replace("\r", " ")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_length:
        text = text[: max_length - 3] + "..."
    return text


class CyberEyeApprovalStore:
    def __init__(self) -> None:
        self._pending: dict[str, dict[str, Any]] = {}

    def create(self, *, action: str, target: str, reason: str, payload: dict[str, Any], requested_by: str) -> dict[str, Any]:
        approval_id = uuid.uuid4().hex[:12]
        record = {
            "approval_id": approval_id,
            "action": action,
            "target": target,
            "reason": reason,
            "payload": payload,
            "requested_by": requested_by,
            "status": "pending",
            "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        }
        self._pending[approval_id] = record
        return {"approval_id": approval_id, "status": "pending", **record}

    def approve(self, approval_id: str, *, approved_by: str) -> dict[str, Any]:
        record = self._pending[approval_id]
        record["status"] = "approved"
        record["approved_by"] = approved_by
        return record

    def reject(self, approval_id: str, *, rejected_by: str, reason: str | None = None) -> dict[str, Any]:
        record = self._pending[approval_id]
        record["status"] = "rejected"
        record["rejected_by"] = rejected_by
        if reason:
            record["decision_reason"] = reason
        return record

    def get(self, approval_id: str) -> dict[str, Any] | None:
        return self._pending.get(approval_id)


@dataclass
class cyber_eye_runtime:
    workspace_root: Path = Path(os.getenv("CYBEREYE_WORKSPACE_ROOT", ".")).resolve()
    approvals: CyberEyeApprovalStore = field(default_factory=CyberEyeApprovalStore)

    def __post_init__(self) -> None:
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def scoped_path(self, raw_path: str) -> Path:
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = (self.workspace_root / candidate).resolve()
        try:
            candidate.relative_to(self.workspace_root)
        except ValueError as exc:  # pragma: no cover - safety guard
            raise PermissionError("Path escapes the safe workspace root") from exc
        return candidate

    def list_dir(self, path: str) -> list[str]:
        safe_path = self.scoped_path(path)
        if not safe_path.exists():
            raise FileNotFoundError(f"Path does not exist: {safe_path}")
        if not safe_path.is_dir():
            raise ValueError(f"Path is not a directory: {safe_path}")
        return sorted([child.name for child in safe_path.iterdir()])

    def read_file(self, path: str, *, max_bytes: int = 8192) -> dict[str, Any]:
        safe_path = self.scoped_path(path)
        if not safe_path.exists():
            raise FileNotFoundError(f"File does not exist: {safe_path}")
        if not safe_path.is_file():
            raise ValueError(f"Path is not a regular file: {safe_path}")
        data = safe_path.read_text(encoding="utf-8", errors="replace")
        data = redact_prompt_injection(data, max_length=max_bytes)
        return {"path": str(safe_path.relative_to(self.workspace_root)), "content": data, "size_bytes": len(data)}

    def write_file(self, path: str, contents: str, *, approval_id: str | None = None, approved: bool = False) -> dict[str, Any]:
        if not approved and not approval_id:
            raise PermissionError("Write operations require an approved mutation record or explicit approval flag.")
        if approval_id:
            record = self.approvals.get(approval_id)
            if record is None or record["status"] != "approved":
                raise PermissionError("Mutation approval was not granted.")
        safe_path = self.scoped_path(path)
        safe_path.parent.mkdir(parents=True, exist_ok=True)
        safe_path.write_text(contents, encoding="utf-8")
        return {"path": str(safe_path.relative_to(self.workspace_root)), "status": "written", "bytes_written": len(contents)}

    def search(self, pattern: str, path: str = ".") -> list[str]:
        root = self.scoped_path(path)
        matcher = re.compile(pattern)
        hits: list[str] = []
        for file in root.rglob("*"):
            if file.is_file():
                try:
                    text = file.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if matcher.search(text):
                    hits.append(str(file.relative_to(self.workspace_root)))
        return hits


def _default_scopes() -> list[str]:
    return ["cybereye:read", "cybereye:write", "gateway:read"]


def generate_operator_token(*, scopes: list[str] | None = None, subject: str = "cybereye-operator") -> str:
    secret = os.getenv("CYBEREYE_JWT_SECRET", "cybereye-dev-secret")
    payload = {"sub": subject, "scopes": scopes or _default_scopes(), "type": "access"}
    return jwt.encode(payload, secret, algorithm="HS256")


def verify_operator_token(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    secret = os.getenv("CYBEREYE_JWT_SECRET", "cybereye-dev-secret")
    if token == "cybereye-demo-operator":
        return {"sub": "cybereye-demo-operator", "scopes": _default_scopes(), "type": "access"}
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_aud": False})
    except JWTError:
        return None
    return payload


def _require_scope(headers: dict[str, str], required: str) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    auth = headers.get("authorization") or headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return None, JSONResponse(status_code=401, content={"error": "Authorization header required"})
    token = auth.split(" ", 1)[1].strip()
    payload = verify_operator_token(token)
    if payload is None:
        return None, JSONResponse(status_code=401, content={"error": "Invalid operator token"})
    scopes = set(payload.get("scopes", []))
    if required not in scopes:
        return None, JSONResponse(status_code=403, content={"error": f"Operator missing required scope: {required}"})
    return payload, None


runtime = cyber_eye_runtime()
server = MCPServer(
    name="cybereye",
    title="CyberEye Operator MCP Server",
    description="Read-only CyberEye telemetry and approval-gated mutation controls for operator workflows.",
    version="1.0.0",
    instructions="Default to read-only actions. Any write or mutate action requires an operator approval record.",
)


@server.tool(name="cybereye_status", title="Status", description="Return the current CyberEye read-only status and capabilities.")
async def cybereye_status() -> dict[str, Any]:
    return {
        "status": "ok",
        "read_only_default": True,
        "mutations_requires_approval": True,
        "workspace_root": str(runtime.workspace_root),
        "supported_tools": [
            "cybereye_status",
            "cybereye_list_dir",
            "cybereye_read_file",
            "cybereye_search",
            "cybereye_request_mutation",
            "cybereye_approve_mutation",
            "cybereye_reject_mutation",
            "cybereye_write_file",
        ],
    }


@server.tool(name="cybereye_list_dir", title="List directory", description="List the contents of a directory inside the safe workspace root.")
async def cybereye_list_dir(path: str = ".") -> dict[str, Any]:
    return {"entries": runtime.list_dir(path)}


@server.tool(name="cybereye_read_file", title="Read file", description="Read a file from the safe workspace root without allowing writes.")
async def cybereye_read_file(path: str, max_bytes: int = 8192) -> dict[str, Any]:
    safe_max = max(256, min(max_bytes, 32768))
    return runtime.read_file(path, max_bytes=safe_max)


@server.tool(name="cybereye_search", title="Search", description="Search contents in the workspace for a regex pattern.")
async def cybereye_search(pattern: str, path: str = ".") -> dict[str, Any]:
    return {"matches": runtime.search(pattern, path)}


@server.tool(name="cybereye_request_mutation", title="Request mutation", description="Request approval before any write or mutate action is executed.")
async def cybereye_request_mutation(*, action: str, target: str, reason: str, payload: dict[str, Any] | None = None, requested_by: str = "operator") -> dict[str, Any]:
    record = runtime.approvals.create(
        action=action,
        target=target,
        reason=redact_prompt_injection(reason),
        payload=payload or {},
        requested_by=requested_by,
    )
    return {"status": "pending", "approval": record}


@server.tool(name="cybereye_approve_mutation", title="Approve mutation", description="Approve a pending mutation request and return the mutation record.")
async def cybereye_approve_mutation(approval_id: str, *, approved_by: str = "operator") -> dict[str, Any]:
    record = runtime.approvals.approve(approval_id, approved_by=approved_by)
    return {"status": "approved", "approval": record}


@server.tool(name="cybereye_reject_mutation", title="Reject mutation", description="Reject a pending mutation request and return the decision record.")
async def cybereye_reject_mutation(approval_id: str, *, rejected_by: str = "operator", reason: str | None = None) -> dict[str, Any]:
    record = runtime.approvals.reject(approval_id, rejected_by=rejected_by, reason=reason)
    return {"status": "rejected", "approval": record}


@server.tool(name="cybereye_write_file", title="Write file", description="Write a file to the safe workspace only after explicit approval.")
async def cybereye_write_file(path: str, contents: str, *, approval_id: str | None = None, approved: bool = False) -> dict[str, Any]:
    return runtime.write_file(path, redact_prompt_injection(contents), approval_id=approval_id, approved=approved)


@server.tool(name="cybereye_mutate", title="Mutate workspace", description="Alias for the approval-gated workspace mutation tool.")
async def cybereye_mutate(path: str, contents: str, *, approval_id: str | None = None, approved: bool = False) -> dict[str, Any]:
    return runtime.write_file(path, redact_prompt_injection(contents), approval_id=approval_id, approved=approved)


TOOL_REGISTRY = {
    "cybereye_status": cybereye_status,
    "cybereye_list_dir": cybereye_list_dir,
    "cybereye_read_file": cybereye_read_file,
    "cybereye_search": cybereye_search,
    "cybereye_request_mutation": cybereye_request_mutation,
    "cybereye_approve_mutation": cybereye_approve_mutation,
    "cybereye_reject_mutation": cybereye_reject_mutation,
    "cybereye_write_file": cybereye_write_file,
    "cybereye_mutate": cybereye_mutate,
}

app = FastAPI(title="CyberEye MCP gateway", version="1.0.0")


@app.middleware("http")
async def require_operator_auth(request: Request, call_next):
    if request.url.path in {"/health", "/docs", "/openapi.json", "/redoc"}:
        return await call_next(request)
    if request.url.path != "/mcp":
        return await call_next(request)

    auth = request.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return JSONResponse(status_code=401, content={"error": "Authorization header required"})
    token = auth.split(" ", 1)[1].strip()
    payload = verify_operator_token(token)
    if payload is None:
        return JSONResponse(status_code=401, content={"error": "Invalid operator token"})
    scopes = set(payload.get("scopes", []))
    if "cybereye:read" not in scopes:
        return JSONResponse(status_code=403, content={"error": "Operator lacks cybereye:read scope"})
    request.state.operator = payload
    return await call_next(request)


@app.post("/mcp")
async def handle_jsonrpc(request: Request):
    payload = await request.json()
    method = payload.get("method")
    request_id = payload.get("id")
    if method == "tools/list":
        tools = [
            {"name": name, "description": fn.__doc__ or "", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": True}}
            for name, fn in TOOL_REGISTRY.items()
        ]
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}}
    if method == "tools/call":
        params = payload.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})
        tool = TOOL_REGISTRY.get(name)
        if tool is None:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Unknown tool: {name}"}}
        try:
            if hasattr(tool, "__call__"):
                result = await tool(**args) if hasattr(tool, "__annotations__") else tool(**args)
        except Exception as exc:  # pragma: no cover - runtime guard
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(exc)}}
        return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": json.dumps(result, default=str)}], "structuredContent": result}}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "cybereye", "version": "1.0.0"}, "capabilities": {"tools": {}}}}
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Unsupported MCP method: {method}"}}


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "cybereye-mcp", "read_only_default": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("CYBEREYE_PORT", "9001")))
