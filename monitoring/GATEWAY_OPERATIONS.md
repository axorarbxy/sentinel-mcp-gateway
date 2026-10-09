# Gateway operations and deployment

Sentinel-MCP is an application gateway. It validates MCP traffic and exposes
management/telemetry APIs; it does not expose database tables as public APIs.

## Production security

Terminate TLS at an ingress or reverse proxy and forward requests to the
gateway only over a private network. Set these environment variables in that
deployment:

```text
SENTINEL_FORCE_HTTPS=true
SENTINEL_ALLOWED_HOSTS=api.example.com
SENTINEL_RATE_LIMIT_REQUESTS=60
SENTINEL_RATE_LIMIT_WINDOW_SECONDS=60
SENTINEL_CIRCUIT_BREAKER_FAILURES=3
SENTINEL_CIRCUIT_BREAKER_RESET_SECONDS=30
SECRET_KEY=<stable-secret-from-your-secret-manager>
```

`SENTINEL_FORCE_HTTPS` must not be enabled for a plain HTTP local development
server. Never place TLS keys, JWT secrets, or API keys in the repository.

Management endpoints under `/mcp/*` require a JWT with the `gateway:admin`
OAuth scope. MCP traffic at `/mcp/proxy` uses a separate agent API key.

## Monitoring and failure behavior

`GET /metrics` and the `performance` object in `GET /stats` report request
count, average latency, throughput, status codes, errors, and rate limiting.
Every HTTP response includes `X-Request-ID` and `X-Response-Time-Ms` for
correlation. Repeated failed upstream MCP server health checks open a circuit
breaker; it returns 503 until the configured cooldown ends.

## Plugins

For auditable extensions such as custom logging or authentication integration,
set `SENTINEL_GATEWAY_PLUGINS` to comma-separated `module:callable` targets.
Hooks receive `(event, data)` for `mcp.request_received` and `mcp.decision`.
Plugin exceptions are isolated and logged, so an optional extension cannot
bring down traffic enforcement. Review and version plugin source in Git before
deployment.

## Source control and CI/CD

Keep gateway configuration in reviewed environment templates or infrastructure
code, not in the database or source. Protect the main branch, require review,
run Python compilation/import tests and the frontend TypeScript check on every
pull request, and promote the same immutable build through environments.
Record policy changes through the management API/audit log and export them to
version-controlled policy definitions before production rollout.
