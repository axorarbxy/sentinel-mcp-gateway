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

# Optional: Redis-backed shared coordination and event delivery
pip install -r requirements-redis.txt

\# Copy environment settings
cp .env.example .env

\# Start the backend from the repository root (Windows PowerShell)
$env:PYTHONUTF8='1'
$env:PYTHONIOENCODING='utf-8'
$env:SENTINEL_REDIS_URL='redis://127.0.0.1:6379/0'  # Optional; enables Redis Streams and cross-worker coordination
python -m uvicorn backend.gateway:app --host 127.0.0.1 --port 8001

\# Start the frontend (separate terminal)
cd frontend
npm install
npm start

\# Example: register a demo admin account, then sign in
curl -X POST http://localhost:8001/auth/register -H "Content-Type: application/json" -d '{"username":"ops","email":"ops@example.com","password":"StrongPass123","full_name":"Ops"}'
curl -X POST http://localhost:8001/auth/login -H "Content-Type: application/json" -d '{"username_or_email":"ops","password":"StrongPass123"}'

\# Demo registration creates an admin-capable account for local use.
\# Existing local demo accounts are promoted after a successful login.
\# Production registrations remain read-only unless separately provisioned.
\# Use the returned access_token for gateway:admin control-plane endpoints.
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
implement the legacy standalone GET/SSE transport. Registered agents can be
assigned their own trusted HTTP upstream; unset agent destinations inherit the
gateway default. JSON-RPC batch arrays are handled as
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

Configure an optional default upstream in the gateway environment. Operators
can also assign an HTTP(S) upstream URL and display name to an individual agent
when registering it in the MCP dashboard. The URL is accepted only through the
operator-protected agent management API, never from MCP request bodies. The
default upstream bearer credential remains gateway-wide and is sent to the
default upstream. For a per-agent URL, select a gateway environment-variable
name in the agent form; that variable's value is sent only to that agent's
upstream. This avoids leaking the default credential to another server.

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
`permissive` logs and forwards them. Keep upstream credentials out of URLs.
Each agent's configured URL overrides the environment default. An empty
effective upstream URL fails closed with HTTP 503. Upstream errors and
invalid responses become JSON-RPC gateway errors instead of exposing upstream
details. No automatic retries are made.

### Route Codex MCP traffic through Sentinel

For a local stdio-only MCP server, first expose it to the gateway using
`backend/sentinel_stdio_upstream.py`. Run one adapter per local server. For
example, from the repository root in PowerShell:

```powershell
$env:SENTINEL_STDIO_COMMAND = "npx"
$env:SENTINEL_STDIO_ARGS_JSON = '["-y","@modelcontextprotocol/server-filesystem","C:\\Data"]'
venv\Scripts\python.exe -m uvicorn backend.sentinel_stdio_upstream:app --host 127.0.0.1 --port 8765
```

The adapter is bound to loopback and exposes that process at
`http://127.0.0.1:8765/mcp`. Set this as the registered Sentinel agent's
upstream URL. The adapter can pass child-process environment variables with
`SENTINEL_STDIO_ENV_JSON` (a JSON object of strings) and a working directory
with `SENTINEL_STDIO_CWD`.

Then use the **Copy Codex config** button shown once when the agent is
registered. It adds `backend/sentinel_mcp_stdio_bridge.py` as a Codex stdio MCP
server; the bridge sends requests through Sentinel with that agent's key.
Adjust the script path if the repository is elsewhere. Keep the local Codex
`config.toml` private because it contains the one-time key. If an MCP server is
already configured directly in Codex, remove or disable that direct entry so
it cannot bypass Sentinel.

```toml
[mcp_servers.sentinel]
command = "python"
args = ["R:\\sentinel-mcp-gateway\\backend\\sentinel_mcp_stdio_bridge.py"]
env = { SENTINEL_AGENT_API_KEY = "<one-time-agent-key>" }
```

The bridge defaults to `http://127.0.0.1:8001/mcp/proxy`; override it with
`SENTINEL_GATEWAY_URL` if needed. Restart Codex after configuration, call an
MCP tool, and confirm the event appears in Sentinel. This covers MCP calls
routed through the bridge; it does not observe Codex prompts, built-in
shell/file tools, or direct network access. The stdio adapter supports
request-response MCP methods; server-initiated requests such as sampling are
not relayed yet.

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

### Adaptive per-agent behavior baseline

The behavioral monitor complements fixed policy rules with an Isolation Forest
for each agent. It learns MCP method mix, tool novelty and use frequency,
request timing, and bounded argument-shape signals (encoded size, nesting,
key count, and string volume); raw arguments are not added to these new model
features. Models start scoring after 20 allowed observations and periodically
refit on the latest bounded window as that agent's workload changes. Only
requests whose enforcement decision is `allow` update the baseline; blocked
and policy-flagged requests cannot train it. An anomaly adds a behavioral alert
and `ml_anomaly` telemetry without changing the synchronous allow/block result.
On startup, the monitor rebuilds its per-agent history from retained gateway
events. Each gateway worker maintains its own live model and reconstructs it
from shared persistence when it starts.

### Durable event pipeline

MCP enforcement remains synchronous: the gateway evaluates the request and
allows, flags, or blocks it before forwarding. Event delivery is decoupled from
that decision path. In the same database transaction that stores each
`mcp_request_events` audit row, the gateway inserts a redacted record into
`mcp_event_outbox`. A background publisher leases pending rows, retries broker
failures with backoff, and appends successful deliveries to the versioned
Redis Stream configured by `SENTINEL_REDIS_KEY_PREFIX`.
After `SENTINEL_OUTBOX_MAX_ATTEMPTS` failures (default 12), an outbox row is
retained with `status=dead_letter`, a timestamp, and a non-sensitive error type
for operator review.

The live dashboard is a Redis Streams consumer group. A consumer acknowledges
an entry only after handling it; entries left pending by a crashed worker are
claimed again after 30 seconds. Each entry carries `event_id`, `event_type`,
`schema_version`, `occurred_at`, `agent_id`, `decision`, `severity`, and the
sanitized event payload. These fields support consumer-side routing and
content filters. The stream is capped by `SENTINEL_EVENT_STREAM_MAXLEN` (default
100,000 entries); the database audit table remains the long-term query history.

#### Protect events from the broker

Set `SENTINEL_EVENT_ENCRYPTION_KEY` to a base64-encoded, random 32-byte topic
key and `SENTINEL_EVENT_SIGNING_PRIVATE_KEY` to a base64-encoded, random
32-byte Ed25519 private seed on publishers. Give authorized subscribers the
same topic key and `SENTINEL_EVENT_SIGNING_PUBLIC_KEY`, derived from that seed.
The gateway dashboard can derive the public key from its private key, but an
independent subscriber should receive only the public key. Distribute keys
through a secret manager or another trusted channel, and rotate them together
with a coordinated subscriber rollout. Generate a key set with:

```python
import base64, secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

private_seed = secrets.token_bytes(32)
public_key = Ed25519PrivateKey.from_private_bytes(private_seed).public_key()
public_bytes = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print("SENTINEL_EVENT_ENCRYPTION_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode())
print("SENTINEL_EVENT_SIGNING_PRIVATE_KEY=" + base64.b64encode(private_seed).decode())
print("SENTINEL_EVENT_SIGNING_PUBLIC_KEY=" + base64.b64encode(public_bytes).decode())
```

With these settings, event payloads are encrypted with AES-256-GCM before they
enter Redis Streams or cross-worker pub/sub. Ed25519 signatures cover both the
ciphertext and routing header; subscribers verify the signature before
decrypting and reject unencrypted messages while protection is enabled. Brokers
can route using the topic, event type, agent, decision, severity, and event ID,
but cannot read payloads or forge events. All subscribers with the topic key can
read that topic, so use separate keys/topics where subscriber groups require
different access. The existing transactional outbox, retries, dead-letter
queue, stream acknowledgements, and pending-entry recovery provide delivery
resilience; cryptography detects broker tampering but cannot prevent a broker
from deliberately withholding or deleting messages. Without these key settings,
the pipeline retains its existing plaintext broker mode.

The live WebSocket accepts private `subscribe` filters for agent IDs, event
types, and decisions. The gateway applies them only after the broker message has
been authenticated and decrypted, so subscription choices are not published to
Redis. Browser control messages are size- and rate-limited, each worker caps
concurrent live connections, WebSocket ticket creation is rate-limited per
operator and source IP, and a slow socket is dropped instead of holding up
event fan-out. In production the gateway requires an authenticated Redis ACL
account and, by default, a `rediss://` transport; set
`SENTINEL_REDIS_REQUIRE_TLS=false` only when TLS is terminated by a trusted
network layer. Restrict the Redis ACL to this application's stream and pub/sub
keys and commands. These controls protect the routing fabric from unauthorized
access and reduce resource-exhaustion risk; infrastructure-level quotas and
replication remain necessary for broker outages and host failures.

#### MQTT, Kafka, and event correlation

Redis remains the gateway's durable internal stream. To fan out protected event
envelopes to device-facing MQTT and/or Kafka pipelines, install
`requirements-event-transports.txt` and set, for example,
`SENTINEL_EVENT_TRANSPORTS=redis,mqtt,kafka`. MQTT uses QoS 1 and its own
`SENTINEL_MQTT_URL`, topic, and credentials; Kafka uses an `acks=all` producer,
an event-ID record key, and its own bootstrap servers, topic, and security
settings. In production MQTT must use `mqtts://` and Kafka must use `SASL_SSL`;
the gateway refuses to start with incomplete secure broker configuration.
Redis, MQTT, and Kafka consumers should deduplicate by the signed `event_id`:
the outbox retries delivery at least once, so a sink that succeeded before a
different sink failed can see the same event again. Keep Redis in the transport
list for dashboard delivery and shared CEP state.

The built-in shared-window CEP emits a `security_correlation` event and alert
when one agent reaches five blocked/flagged requests within two minutes, or
when the same detection rule appears across three agents within five minutes.
Thresholds and windows are configurable with the `SENTINEL_CEP_*` variables.
Window membership is deduplicated by event ID and stored atomically in Redis,
so multiple gateway workers share one correlation view. These are starter rules;
Kafka Streams, Flink, or another dedicated CEP system can consume the same
versioned, signed event envelopes for richer sequences and long-term state.

The stream consumer also uses an atomic shared event-ID lease and a completed
ID cache (24 hours by default) before delivering an event. Failed handlers
release their lease so Redis can retry; successful deliveries are acknowledged
and repeated signed envelopes are ignored during the retention window. Adaptive
behavior anomalies now become high-severity correlation alerts, and anomalous
calls to sensitive action tools (such as `publish`, `execute`, `delete`, or
`transfer`) receive a separate rule ID. When that behavior or a block/flag is
present, matching 64-character payload fingerprints across three agents in
five minutes raise `CEP-PUBLISHER-FANOUT-COLLUSION`. Tune that threshold and
window with `SENTINEL_CEP_FANOUT_AGENT_THRESHOLD` and
`SENTINEL_CEP_FANOUT_WINDOW_SECONDS`; replay-cache retention is controlled by
`SENTINEL_EVENT_REPLAY_RETENTION_SECONDS`. These are investigation signals;
they do not automatically block schema-valid requests.

Set `SENTINEL_REDIS_URL` to enable Redis-backed streams and cross-worker
delivery; Redis 6.2 or newer is required for Streams consumer groups. Older
Redis versions use the existing pub/sub live-feed transport while retaining the
database outbox and audit history. The in-memory development adapter supports
the same event API for one process, but is not durable across restarts or shared
across workers. Outbox rows remain in the database after publishing, and failed
publishes are retried without changing the already-made allow/block decision.

For local development, SQLite stores the event history and agent records in
`database/sentinel_mcp.db`. The default path is anchored to the project files,
so stopping and restarting the gateway (even from another working directory)
continues to use the same database. Keep that file when preserving local data;
set `DATABASE_URL` only when intentionally selecting a different persistent
database.

| Condition | Gateway behavior |
| --- | --- |
| Invalid JSON-RPC, duplicate keys, bad encoding | HTTP 400 with a JSON-RPC error |
| Oversized/deep request or oversized upstream response | HTTP 413 on request; upstream failure becomes JSON-RPC/HTTP 502 |
| Disallowed tool or decision-hook failure/timeout | JSON-RPC error; upstream is not called |
| Unknown, cross-agent, or cross-upstream MCP session | HTTP 404 with a JSON-RPC error and `GATEWAY-SESSION-BOUNDARY` audit rule |
| Missing upstream configuration | HTTP 503 with a JSON-RPC error |
| Upstream unavailable, invalid reply, or unsupported response type | HTTP 502 with a non-sensitive JSON-RPC error |
| Accepted notification | HTTP 202 with no body |

MCP session IDs are bound to both the authenticated agent and a credential-free
fingerprint of the configured upstream (scheme, host, port, path, and registered
upstream name). Every request using a session must match both identities. Changing
an agent's upstream therefore invalidates its old session at the gateway boundary;
the client must establish a new MCP session with the newly configured upstream.

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
