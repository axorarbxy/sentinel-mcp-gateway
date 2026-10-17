"""Forward a Codex stdio MCP connection through Sentinel's HTTP gateway.

Configure this script as a Codex stdio MCP server. It deliberately writes only
MCP JSON-RPC messages to stdout; diagnostics are written to stderr.
"""

from __future__ import annotations

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


GATEWAY_URL = os.getenv("SENTINEL_GATEWAY_URL", "http://127.0.0.1:8001/mcp/proxy")
AGENT_KEY = os.getenv("SENTINEL_AGENT_API_KEY", "")
MAX_MESSAGE_BYTES = 1_048_576
TIMEOUT_SECONDS = float(os.getenv("SENTINEL_BRIDGE_TIMEOUT_SECONDS", "60"))


def _response_payload(body: bytes, content_type: str):
    if "text/event-stream" in content_type.lower():
        for line in body.decode("utf-8", errors="replace").splitlines():
            if line.startswith("data:"):
                data = line[5:].strip()
                if data:
                    return json.loads(data)
        raise ValueError("Sentinel returned an MCP event stream without a data frame")
    return json.loads(body.decode("utf-8"))


def _forward(message: dict, session_id: str | None, protocol_version: str | None):
    headers = {
        "Authorization": f"Bearer {AGENT_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["MCP-Session-Id"] = session_id
    if protocol_version:
        headers["MCP-Protocol-Version"] = protocol_version
    request = Request(
        GATEWAY_URL,
        data=json.dumps(message, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_MESSAGE_BYTES + 1)
            if len(body) > MAX_MESSAGE_BYTES:
                raise ValueError("Sentinel response exceeded the configured bridge limit")
            next_session = response.headers.get("MCP-Session-Id", session_id)
            next_protocol = response.headers.get("MCP-Protocol-Version", protocol_version)
            if not body:
                return None, next_session, next_protocol
            return _response_payload(body, response.headers.get("Content-Type", "")), next_session, next_protocol
    except HTTPError as response:
        body = response.read(MAX_MESSAGE_BYTES + 1)
        try:
            payload = _response_payload(body, response.headers.get("Content-Type", ""))
        except Exception:
            payload = {"jsonrpc": "2.0", "id": message.get("id"), "error": {
                "code": -32000, "message": f"Sentinel gateway returned HTTP {response.code}",
            }}
        return payload, response.headers.get("MCP-Session-Id", session_id), protocol_version


def main() -> int:
    if not AGENT_KEY:
        print("SENTINEL_AGENT_API_KEY is not set", file=sys.stderr)
        return 2
    session_id = None
    protocol_version = None
    for raw_line in sys.stdin.buffer:
        if len(raw_line) > MAX_MESSAGE_BYTES:
            print("MCP input line exceeded the configured size limit", file=sys.stderr)
            return 2
        message = None
        try:
            message = json.loads(raw_line)
            if not isinstance(message, dict):
                continue
            if message.get("method") == "initialize":
                params = message.get("params")
                if isinstance(params, dict) and isinstance(params.get("protocolVersion"), str):
                    protocol_version = params["protocolVersion"]
            response, session_id, protocol_version = _forward(message, session_id, protocol_version)
            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":"), ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except (json.JSONDecodeError, OSError, URLError, TimeoutError, ValueError) as exc:
            print(f"Sentinel MCP bridge error: {type(exc).__name__}: {exc}", file=sys.stderr)
            if isinstance(message, dict) and "id" in message:
                failure = {"jsonrpc": "2.0", "id": message["id"], "error": {
                    "code": -32000, "message": "Sentinel gateway request failed",
                }}
                sys.stdout.write(json.dumps(failure, separators=(",", ":")) + "\n")
                sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
