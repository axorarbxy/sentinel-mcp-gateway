\# 🛡️ Sentinel-MCP Gateway



\### AI/ML Security Monitoring Framework for MCP-Connected Ecosystems



\[!\[Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

\[!\[FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-green.svg)](https://fastapi.tiangolo.com/)

\[!\[Research](https://img.shields.io/badge/Research-SECUREVENT%202026-red.svg)](https://arxiv.org/abs/2606.01741)

\[!\[License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)



\---



\## 📋 Overview



\*\*Sentinel-MCP\*\* is a cutting-edge security monitoring framework for AI agents using the Model Context Protocol (MCP). Built on 2026 research foundations, it provides \*\*three-layer defense\*\*:



1\. \*\*Rule-based Policy Engine\*\* - Blocks dangerous operations (path traversal, malicious commands, SQL injection)

2\. \*\*Behavioral Analysis\*\* - Detects suspicious patterns (rapid requests, unusual timing, operation chains)

3\. \*\*ML Anomaly Detection\*\* - Uses Isolation Forest to identify behavioral deviations



\### 🎯 Why This Matters



> \*"MCP servers wrapping offensive tools introduce higher risk than skill-based resources"\* - 2026 MCP Security Research



As AI agents gain access to more tools (filesystem, shell, databases, network), securing the \*\*MCP communication layer\*\* becomes critical. Sentinel-MCP acts as a \*\*security proxy\*\* between AI agents and their tools, ensuring every operation is validated, monitored, and audited.



\---



\## 🔬 Research Foundation



This project implements the hybrid approach proposed in:



| Paper | Year | Contribution |

|-------|------|--------------|

| \*\*SECUREVENT\*\* (arXiv 2606.01741) | 2026 | Hybrid AI/ML monitoring for distributed event systems |

| \*\*MCP Security Analysis\*\* | 2026 | MCP attack surface identification |

| \*\*Agentic SOC Evolution\*\* | 2026 | AI-powered security operations |



\*\*Key Research Contributions:\*\*

\- ✅ Online anomaly detection for event-based systems

\- ✅ Graph-aware behavioral feature extraction

\- ✅ Policy-as-code integration with model scoring

\- ✅ MITRE ATLAS mapping for AI-specific threats



\---



\## ✨ Features



\### 🔒 Security Policies

\- \*\*Path Traversal Prevention\*\* - Blocks access to `/etc/passwd`, `.env`, `.git`, etc.

\- \*\*Command Whitelisting\*\* - Only allows safe commands (`ls`, `pwd`, `whoami`, etc.)

\- \*\*SQL Injection Protection\*\* - Detects `DROP`, `DELETE`, `TRUNCATE`, and other dangerous patterns

\- \*\*Zero-Trust Architecture\*\* - Block by default, allow explicitly



\### 🧠 ML Anomaly Detection

\- \*\*Behavioral Profiling\*\* - Learns normal agent behavior patterns

\- \*\*Isolation Forest\*\* - Unsupervised anomaly detection

\- \*\*Feature Engineering\*\* - Extracts 15+ behavioral features:

&#x20; - Request frequency and timing

&#x20; - Method type distribution

&#x20; - Parameter complexity

&#x20; - Command length and structure

&#x20; - SQL complexity patterns

\- \*\*Real-time Detection\*\* - Identifies anomalies within milliseconds



\### 📊 Monitoring \& Auditing

\- \*\*Request Logging\*\* - Complete audit trail of all MCP operations

\- \*\*Alert System\*\* - Real-time anomaly alerts

\- \*\*Statistics Dashboard\*\* - Visualize block rates, method distribution, anomaly counts

\- \*\*Agent Profiling\*\* - Per-agent behavioral models



\### 🎯 MITRE ATLAS Ready

Maps security violations to MITRE ATLAS techniques:

\- AML.T0086 - Exfiltration via AI Agent Tool Invocation

\- AML.T0043 - Adversarial AI System Compromise

\- AML.T0010 - Data Poisoning via AI System Input



\---



\## 🚀 Quick Start



\### Prerequisites

\- Python 3.11 or higher

\- Git



\### Installation



```bash

\# Clone the repository

git clone https://github.com/axorarbxy/sentinel-mcp-gateway.git

cd sentinel-mcp-gateway



\# Create virtual environment

python -m venv venv



\# Activate virtual environment

\# Windows:

venv\\Scripts\\activate

\# Mac/Linux:

source venv/bin/activate



\# Install dependencies

pip install -r requirements.txt

\# Copy environment settings
cp .env.example .env

\# Start the backend from the repository root (Windows PowerShell)
$env:PYTHONUTF8='1'
$env:PYTHONIOENCODING='utf-8'
python -m uvicorn backend.gateway:app --host 127.0.0.1 --port 8001

\# Start the frontend (separate terminal)
cd frontend
npm install
npm start

\# Example: register a read-only operator account, then sign in
curl -X POST http://localhost:8001/auth/register -H "Content-Type: application/json" -d '{"username":"ops","email":"ops@example.com","password":"StrongPass123","full_name":"Ops"}'
curl -X POST http://localhost:8001/auth/login -H "Content-Type: application/json" -d '{"username_or_email":"ops","password":"StrongPass123"}'

\# Registration does not grant gateway:admin; provision an administrator separately.
\# Use the returned access_token for read-authorized control-plane endpoints.
```

## Agent API key authentication

Agent keys use `cye_test_<lookup-id>_<random-secret>` in development and
`cye_live_<lookup-id>_<random-secret>` when `SENTINEL_ENVIRONMENT` is
`production`/`prod`. The random component is generated with a cryptographic RNG
(256 bits); only its SHA-256 hash and indexed lookup ID are stored. The full key
is returned only by registration or rotation and must never be put in a URL.
Send it only as `Authorization: Bearer <one-time-agent-key>`.

```bash
curl -i http://localhost:8001/mcp/proxy \
  -H "Authorization: Bearer cye_test_<lookup-id>_<random-secret>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}'
```

An invalid/unknown/revoked key returns `401`; a suspended agent returns `403`;
authentication or per-agent traffic limits return `429` with `Retry-After`.
Malformed, duplicate, oversized, query-string, and `X-API-Key` credentials are
rejected. A suspended agent can be resumed through the operator-authenticated
management API. Rotate a key with an optional grace window of up to 300 seconds:

```bash
curl -X POST "http://localhost:8001/mcp/agents/1/rotate-credential?grace_period_seconds=60" \
  -H "Authorization: Bearer <operator-access-token>"
```

During that grace period the previous and replacement key both work. Without a
grace period (the default), the previous key is invalidated immediately. The
gateway checks current lifecycle state on every request; no key cache delays a
suspend, revoke, or rotation.

Operator access tokens are a separate control-plane credential. They are
required for gateway telemetry, live traffic, and management routes; they are
never accepted as agent keys. The browser obtains a short-lived, one-use
WebSocket ticket using its operator token. Only `/health`, login/registration/
refresh, API documentation, and CORS preflight are public.

Failed attempts and lockouts are audited with the source IP and lookup prefix,
never the presented secret. Authentication failures are limited per source IP
and key prefix; successful traffic is limited per agent. These limits and the
audit/rate-limit state are process-local, so multi-worker or multi-host
deployments should place the service behind a shared rate-limit/audit store.

Use HTTPS for every non-local deployment. Terminate TLS at a trusted ingress or
enable `SENTINEL_FORCE_HTTPS=true` when HTTPS reaches the application directly.
Do not expose the development HTTP listener to an untrusted network. Configure
`SECRET_KEY`, `SENTINEL_ALLOWED_HOSTS`, and `SENTINEL_CORS_ORIGINS` from the
deployment environment; do not use the example secret in production.

Rejected-call example:

```bash
curl -i http://localhost:8001/mcp/proxy \
  -H "Authorization: Bearer not-a-valid-agent-key" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}'
```
## MCP request interception

### Supported transport

The gateway supports MCP Streamable HTTP over a single configured upstream HTTP
endpoint. It accepts authenticated `POST /mcp/proxy` JSON-RPC 2.0 requests and
notifications, forwards JSON responses, and streams request-scoped
`text/event-stream` responses. The proxy preserves `MCP-Protocol-Version` and
binds upstream `MCP-Session-Id` values to the authenticated agent. It does not
launch stdio servers, implement the legacy standalone GET/SSE transport, or
offer arbitrary agent-selected upstreams. JSON-RPC batch arrays are handled as
an extension: each item is evaluated independently and allowed items are
forwarded separately; SSE replies to batch requests are rejected.

The proxy accepts protocol versions `2025-11-25` and `2026-07-28`. For
`2026-07-28`, the `MCP-Protocol-Version` header must match the version in each
message's `_meta` field. Requests without version metadata are treated as
legacy `2025-11-25` clients and the gateway supplies that version upstream.
The downstream origin is checked against `SENTINEL_CORS_ORIGINS`.

```mermaid
flowchart LR
  A[Agent with API key] --> B[POST /mcp/proxy]
  B --> C[Authenticate and bind session]
  C --> D[Validate and normalize JSON-RPC]
  D --> E[Async decision hook]
  E -->|block| F[JSON-RPC error]
  E -->|allow or flag| G[Configured MCP upstream]
  G --> H[Filter tools/list and inspect response]
  H --> I[Redact and persist/stream versioned event]
  H --> A
```

This behavior follows the current [MCP Streamable HTTP transport
specification](https://modelcontextprotocol.io/specification/latest/basic/transports/streamable-http)
and [JSON-RPC message
patterns](https://modelcontextprotocol.io/specification/latest/basic/patterns).
The server validates JSON-RPC 2.0 envelopes, UTF-8, duplicate keys (including
Unicode-normalized collisions), nesting depth, payload size, and batch size.
JSON-RPC notifications receive HTTP 202 when accepted. Invalid messages are
rejected before upstream forwarding.

### Configure an upstream

Configure one trusted upstream in the gateway environment. The URL is never
accepted from agent input; the optional upstream bearer credential is sent
only from the gateway to that configured server.

```dotenv
SENTINEL_MCP_UPSTREAM_URL=https://mcp.internal.example/mcp
SENTINEL_MCP_UPSTREAM_NAME=internal-tools
SENTINEL_MCP_UPSTREAM_TOKEN=
SENTINEL_MCP_UPSTREAM_TIMEOUT_SECONDS=30
SENTINEL_MCP_UNKNOWN_METHOD_MODE=strict
```

The application reads configuration from its process environment; copying
`.env.example` to `.env` does not load it automatically. In PowerShell, set the
upstream values before starting Uvicorn:

```powershell
$env:SENTINEL_MCP_UPSTREAM_URL = "https://mcp.internal.example/mcp"
$env:SENTINEL_MCP_UPSTREAM_NAME = "internal-tools"
$env:SENTINEL_MCP_UPSTREAM_TOKEN = ""
Set-Location (git rev-parse --show-toplevel)
venv\Scripts\python.exe -m uvicorn backend.gateway:app --host 127.0.0.1 --port 8001
```

The timeout defaults to 30 seconds. Unknown methods are blocked by default;
`permissive` logs and forwards them. Configure the upstream URL and token only
through the deployment environment. In particular, do not put credentials in
the URL. An empty upstream URL fails closed with HTTP 503. Upstream errors and
invalid responses become JSON-RPC gateway errors instead of exposing upstream
details. No automatic retries are made.

### Decision hook and event schema

`backend/mcp_interception.py` defines the `InterceptionEvent` and `Decision` data
classes and the asynchronous `decision_hook(event, agent)` extension point.
The default hook only enforces `allowed_tools`, message direction, and the
configured unknown-method mode. `allow`, `block`, and `flag` are supported;
hook exceptions or a timeout block the request. Task 04 policy rules and Task
05 anomaly scoring can be plugged into this hook without changing transport
handling.

Each intercepted message emits a versioned `1.0` event with event/time/session
and request IDs, verified agent identity, direction, method/upstream, tool or
resource/prompt details, decision/reason/rule IDs, latency, response status and
size, source IP, a payload hash, and a bounded redacted payload. Sensitive
field names, bearer tokens, known CyberEye/legacy keys, and PEM private keys
are redacted before persistence or event broadcast. Large payloads are
truncated with a SHA-256 hash. Additional value-redaction regexes can be
configured as a JSON array in `SENTINEL_MCP_REDACTION_PATTERNS`. Events are persisted in `mcp_request_events`,
queryable by agent, method, tool, decision, and time through the
operator-protected endpoint:

```bash
curl -H "Authorization: Bearer <operator-access-token>" \
  "http://localhost:8001/mcp/events?agent_id=1&tool_name=filesystem.read&decision=block&since=2026-10-01T00:00:00&limit=100"
```

The same redacted event is sent through the existing live WebSocket event
channel as `mcp_event`. Persistence or live-feed failures are logged without
including payload data; they do not change the policy decision.

| Condition | Gateway behavior |
| --- | --- |
| Invalid JSON-RPC, duplicate keys, bad encoding | HTTP 400 with a JSON-RPC error |
| Oversized/deep request or oversized upstream response | HTTP 413 on request; upstream failure becomes JSON-RPC/HTTP 502 |
| Disallowed tool or decision-hook failure/timeout | JSON-RPC error; upstream is not called |
| Unknown or cross-agent MCP session | HTTP 404 with a JSON-RPC error |
| Missing upstream configuration | HTTP 503 with a JSON-RPC error |
| Upstream unavailable, invalid reply, or unsupported response type | HTTP 502 with a non-sensitive JSON-RPC error |
| Accepted notification | HTTP 202 with no body |

### Verify a call

Set `SENTINEL_MCP_UPSTREAM_URL`, start the backend and frontend as described in
Quick Start, then use the one-time key returned at agent registration. The
agent's `allowed_tools` must include the exact upstream tool name for the first
call to pass. The MCP client must send `Accept: application/json,
text/event-stream` (or `*/*`):

```bash
curl -i -X POST http://localhost:8001/mcp/proxy \
  -H "Authorization: Bearer <one-time-agent-key>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"README.md"}}}'
```

Use a name not present in the agent's `allowed_tools` to verify blocking; the
response is a JSON-RPC error and that call is not forwarded:

```bash
curl -i -X POST http://localhost:8001/mcp/proxy \
  -H "Authorization: Bearer <one-time-agent-key>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"not-allowed","arguments":{}}}'
```