# Gateway operations

Sentinel-MCP is an application gateway. It validates MCP traffic and exposes
management/telemetry APIs; it does not expose database tables as public APIs.

## Network security

Terminate TLS at an ingress or reverse proxy and forward requests to the
gateway only over a private network. Set these environment variables in the
service environment when it is accessed over a network:

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

## Outbound network policy

The application firewall is an additional MCP-upstream policy layer, not a
replacement for host packet filtering, cloud security groups, network policies,
restricted DNS, or a controlled egress proxy. It is disabled by default for
development. Production startup fails unless
`SENTINEL_NETWORK_FIREWALL_ENABLED=true` and the default action is `BLOCK`.

Configure approved destinations explicitly with `SENTINEL_NETWORK_ALLOWED_DOMAINS`
or the admin-only `/network-firewall/rules` API. The default allowed protocol
and port are HTTPS and 443; private, loopback, and link-local destinations are
blocked. If an internal upstream is required, explicitly set
`SENTINEL_NETWORK_BLOCK_PRIVATE=false` and add a narrowly scoped destination
rule; default-deny remains in effect. The proxy resolves and validates all destination addresses and pins
each outbound connection to a validated result. DNS failures and policy service
errors fail closed. Use `POST /network-firewall/test` to simulate a rule without
DNS lookups or outbound requests.

Management endpoints under `/mcp/*` require a JWT with the `gateway:admin`
OAuth scope. MCP traffic at `/mcp/proxy` uses a separate agent API key.
Network firewall administration endpoints require `gateway:admin`.

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
bring down traffic enforcement. Review plugin source before enabling it.
