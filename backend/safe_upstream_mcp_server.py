from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp.server import MCPServer
from starlette.middleware.base import BaseHTTPMiddleware


class SafeUpstreamFixture:
    def __init__(self, workspace_root: str | Path | None = None) -> None:
        self.workspace_root = Path(workspace_root or os.getenv("SAFE_UPSTREAM_ROOT", "./safe-upstream")).resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def _resolve_path(self, raw_path: str) -> Path:
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = (self.workspace_root / candidate).resolve()
        candidate.relative_to(self.workspace_root)
        return candidate

    def read_file(self, path: str) -> dict[str, Any]:
        candidate = self._resolve_path(path)
        if not candidate.exists() or not candidate.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        return {"path": str(candidate.relative_to(self.workspace_root)), "content": candidate.read_text(encoding="utf-8", errors="replace")}

    def list_dir(self, path: str = ".") -> dict[str, Any]:
        candidate = self._resolve_path(path)
        if not candidate.exists() or not candidate.is_dir():
            raise FileNotFoundError(f"Directory not found: {path}")
        return {"path": str(candidate.relative_to(self.workspace_root)), "entries": sorted(entry.name for entry in candidate.iterdir())}

    def mutate(self, path: str, contents: str, *, approved: bool = False) -> dict[str, Any]:
        if not approved:
            raise PermissionError("Upstream mutation requires explicit approval from a human operator.")
        candidate = self._resolve_path(path)
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text(contents, encoding="utf-8")
        return {"status": "written", "path": str(candidate.relative_to(self.workspace_root)), "bytes": len(contents)}


fixture = SafeUpstreamFixture()
server = MCPServer(
    name="safe-upstream-fixture",
    title="Safe Upstream Fixture",
    description="A read-only MCP fixture that refuses mutations unless an operator explicitly approves them.",
    version="1.0.0",
)


@server.tool(name="upstream_status", title="Status", description="Report safe upstream health and mode.")
async def upstream_status() -> dict[str, Any]:
    return {"status": "ok", "read_only_default": True, "write_requires_explicit_approval": True}


@server.tool(name="upstream_list_dir", title="List directory", description="List a directory in the safe workspace.")
async def upstream_list_dir(path: str = ".") -> dict[str, Any]:
    return fixture.list_dir(path)


@server.tool(name="upstream_read_file", title="Read file", description="Read a file from the safe workspace.")
async def upstream_read_file(path: str) -> dict[str, Any]:
    return fixture.read_file(path)


@server.tool(name="upstream_mutate", title="Mutate", description="Write data to the safe upstream only when approval is explicitly set.")
async def upstream_mutate(path: str, contents: str, *, approved: bool = False) -> dict[str, Any]:
    return fixture.mutate(path, contents, approved=approved)


TOOL_REGISTRY = {
    "upstream_status": upstream_status,
    "upstream_list_dir": upstream_list_dir,
    "upstream_read_file": upstream_read_file,
    "upstream_mutate": upstream_mutate,
}

app = FastAPI(title="Safe Upstream Fixture", version="1.0.0")


@app.middleware("http")
async def allow_read_only_requests(request: Request, call_next):
    if request.method in {"GET", "OPTIONS"}:
        return await call_next(request)
    if request.url.path != "/mcp":
        return await call_next(request)
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
            result = await tool(**args) if callable(tool) and hasattr(tool, "__annotations__") else tool(**args)
        except Exception as exc:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(exc)}}
        return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": json.dumps(result, default=str)}], "structuredContent": result}}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "safe-upstream", "version": "1.0.0"}, "capabilities": {"tools": {}}}}
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Unsupported MCP method: {method}"}}


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "safe-upstream-fixture"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("SAFE_UPSTREAM_PORT", "9002")))
