"""Expose one local stdio MCP server as loopback-only Streamable HTTP.

This lets the Sentinel HTTP gateway inspect a local stdio MCP server. Configure
the target command through SENTINEL_STDIO_COMMAND and SENTINEL_STDIO_ARGS_JSON.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

logger = logging.getLogger("sentinel.stdio_upstream")
MAX_MESSAGE_BYTES = 1_048_576
COMMAND = os.getenv("SENTINEL_STDIO_COMMAND", "").strip()
ARGS = json.loads(os.getenv("SENTINEL_STDIO_ARGS_JSON", "[]"))
CWD = os.getenv("SENTINEL_STDIO_CWD", "").strip() or None
CHILD_ENV = json.loads(os.getenv("SENTINEL_STDIO_ENV_JSON", "{}"))
REQUEST_TIMEOUT = float(os.getenv("SENTINEL_STDIO_TIMEOUT_SECONDS", "60"))


class StdioMCPProcess:
    def __init__(self) -> None:
        self.process: asyncio.subprocess.Process | None = None
        self.lock = asyncio.Lock()

    async def _start(self) -> None:
        if not COMMAND:
            raise RuntimeError("SENTINEL_STDIO_COMMAND is not configured")
        if not isinstance(ARGS, list) or any(not isinstance(arg, str) for arg in ARGS):
            raise RuntimeError("SENTINEL_STDIO_ARGS_JSON must be a JSON array of strings")
        if not isinstance(CHILD_ENV, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in CHILD_ENV.items()):
            raise RuntimeError("SENTINEL_STDIO_ENV_JSON must be a JSON object of string values")
        self.process = await asyncio.create_subprocess_exec(
            COMMAND,
            *ARGS,
            cwd=CWD,
            env={**os.environ, **CHILD_ENV},
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=MAX_MESSAGE_BYTES + 1,
        )

    async def stop(self) -> None:
        process, self.process = self.process, None
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()

    async def request(self, message: dict[str, Any]) -> dict[str, Any] | None:
        async with self.lock:
            if self.process is None or self.process.returncode is not None:
                await self.stop()
                await self._start()
            assert self.process and self.process.stdin and self.process.stdout
            process = self.process
            process.stdin.write(json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n")
            await process.stdin.drain()
            if "id" not in message:
                return None
            try:
                while True:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=REQUEST_TIMEOUT)
                    if not line:
                        raise RuntimeError("stdio MCP server exited without replying")
                    if len(line) > MAX_MESSAGE_BYTES:
                        raise RuntimeError("stdio MCP server response exceeded the size limit")
                    response = json.loads(line)
                    if not isinstance(response, dict):
                        continue
                    # Ignore server notifications. Server-initiated requests that
                    # require a client response are not supported by this adapter.
                    if response.get("id") != message["id"]:
                        continue
                    return response
            except Exception:
                await self.stop()
                raise


stdio_mcp = StdioMCPProcess()


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    await stdio_mcp.stop()


app = FastAPI(title="Sentinel Local stdio MCP Adapter", lifespan=lifespan)


def _is_loopback(request: Request) -> bool:
    try:
        return bool(request.client and ipaddress.ip_address(request.client.host).is_loopback)
    except ValueError:
        return False


@app.post("/mcp")
async def mcp_stdio_upstream(request: Request):
    if not _is_loopback(request):
        return JSONResponse(status_code=403, content={"error": "Loopback clients only"})
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return Response(status_code=415)
    body = await request.body()
    if len(body) > MAX_MESSAGE_BYTES:
        return Response(status_code=413)
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JSONResponse(status_code=400, content={"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
    messages = payload if isinstance(payload, list) else [payload]
    if not messages or any(not isinstance(message, dict) for message in messages):
        return JSONResponse(status_code=400, content={"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
    responses = []
    try:
        for message in messages:
            response = await stdio_mcp.request(message)
            if response is not None:
                responses.append(response)
    except (OSError, RuntimeError, asyncio.TimeoutError, json.JSONDecodeError) as exc:
        logger.error("Local stdio MCP server failed (%s)", type(exc).__name__)
        request_id = messages[0].get("id") if len(messages) == 1 else None
        return JSONResponse(status_code=502, content={"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": "Local MCP server unavailable"}})
    if not responses:
        return Response(status_code=202)
    return JSONResponse(content=responses[0] if len(responses) == 1 else responses)
