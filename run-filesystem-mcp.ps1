# Starts the local filesystem MCP upstream used by Sentinel.
# This exposes read/write/delete tools across the C: and R: drives.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$env:SENTINEL_STDIO_COMMAND = "C:\Program Files\nodejs\node.exe"
$env:SENTINEL_STDIO_ARGS_JSON = '["C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npx-cli.js","-y","@modelcontextprotocol/server-filesystem","C:\\","R:\\"]'

& ".\.venv\Scripts\python.exe" -m uvicorn backend.sentinel_stdio_upstream:app `
    --host 127.0.0.1 --port 8765
