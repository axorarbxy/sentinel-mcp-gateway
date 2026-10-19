"""Ephemeral gateway coordination with an in-memory dev adapter and Redis backend."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Sequence
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

REDIS_PREFIX = os.getenv("SENTINEL_REDIS_KEY_PREFIX", "sentinel")
EVENT_CHANNEL = f"{REDIS_PREFIX}:gateway:events"
CONTROL_CHANNEL = f"{REDIS_PREFIX}:gateway:control"
EVENT_STREAM = f"{REDIS_PREFIX}:gateway:event-stream:v1"
EVENT_STREAM_MAXLEN = max(1000, int(os.getenv("SENTINEL_EVENT_STREAM_MAXLEN", "100000")))
MCP_SESSION_TTL_SECONDS = max(60, int(os.getenv("SENTINEL_MCP_SESSION_TTL_SECONDS", "3600")))
REQUEST_CLAIM_TTL_SECONDS = max(30, int(os.getenv("SENTINEL_MCP_REQUEST_CLAIM_TTL_SECONDS", "300")))


class SharedStateUnavailable(RuntimeError):
    """Raised when required shared coordination cannot be reached."""


def _stable_key(namespace: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{REDIS_PREFIX}:{namespace}:{digest}"


def _bucket_key(key: tuple[str, str]) -> str:
    kind, value = key
    return _stable_key("rate", f"{kind}\0{value}")


class InMemorySharedState:
    """Single-process adapter for development and deterministic unit tests."""

    is_distributed = False

    def __init__(self) -> None:
        self.worker_id = f"{os.getpid()}-{uuid.uuid4().hex}"
        self._lock = threading.RLock()
        self._buckets: dict[str, deque[tuple[float, str | None]]] = defaultdict(deque)
        self._tickets: dict[str, tuple[float, int]] = {}
        self._sessions: dict[str, tuple[int, str, float]] = {}
        self._claims: dict[str, tuple[str, float]] = {}
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._event_stream_queues: dict[str, asyncio.Queue[tuple[str, dict[str, Any]]]] = {}
        self._event_stream_sequence = 0
        self._event_windows: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._event_dedup: dict[str, tuple[str, float]] = {}

    async def connect(self) -> None:
        self.worker_id = f"{os.getpid()}-{uuid.uuid4().hex}"

    async def close(self) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
            self._subscribers.clear()
        for queue in subscribers:
            queue.put_nowait(json.dumps({"kind": "shutdown"}))

    def reset(self) -> None:
        """Clear all ephemeral test/dev state while retaining active subscribers."""
        with self._lock:
            self._buckets.clear()
            self._tickets.clear()
            self._sessions.clear()
            self._claims.clear()
            self._event_windows.clear()
            self._event_dedup.clear()

    def _active_buckets(self, keys: Sequence[tuple[str, str]], window_seconds: int, now: float):
        buckets = []
        for key in keys:
            bucket_key = _bucket_key(key)
            bucket = self._buckets[bucket_key]
            while bucket and now - bucket[0][0] >= window_seconds:
                bucket.popleft()
            buckets.append((bucket_key, bucket))
        return buckets

    async def is_rate_limited(self, keys: Sequence[tuple[str, str]], limit: int, window_seconds: int) -> bool:
        with self._lock:
            return any(len(bucket) >= limit for _, bucket in self._active_buckets(keys, window_seconds, time.monotonic()))

    async def consume_rate_limit(self, keys: Sequence[tuple[str, str]], limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            buckets = self._active_buckets(keys, window_seconds, now)
            if any(len(bucket) >= limit for _, bucket in buckets):
                return False
            for _, bucket in buckets:
                bucket.append((now, None))
            return True

    async def begin_auth_attempt(
        self, keys: Sequence[tuple[str, str]], limit: int, window_seconds: int,
    ) -> str | None:
        now = time.monotonic()
        token = uuid.uuid4().hex
        with self._lock:
            buckets = self._active_buckets(keys, window_seconds, now)
            if any(len(bucket) >= limit for _, bucket in buckets):
                return None
            for _, bucket in buckets:
                bucket.append((now, token))
            return token

    async def finish_auth_attempt(
        self, keys: Sequence[tuple[str, str]], token: str, *, failed: bool,
    ) -> None:
        if failed:
            return
        with self._lock:
            for key in keys:
                bucket = self._buckets.get(_bucket_key(key))
                if bucket is not None:
                    retained = [entry for entry in bucket if not (isinstance(entry, tuple) and entry[1] == token)]
                    self._buckets[_bucket_key(key)] = deque(retained)

    async def put_ws_ticket(self, ticket: str, operator_id: int, ttl_seconds: int) -> None:
        with self._lock:
            self._tickets[ticket] = (time.monotonic() + ttl_seconds, operator_id)

    async def consume_ws_ticket(self, ticket: str) -> int | None:
        with self._lock:
            value = self._tickets.pop(ticket, None)
            if value is None or value[0] <= time.monotonic():
                return None
            return value[1]

    async def bind_mcp_session(
        self, session_id: str, agent_id: int, ttl_seconds: int, upstream_scope: str = "",
    ) -> bool:
        now = time.monotonic()
        with self._lock:
            current = self._sessions.get(session_id)
            if current and current[2] > now and (current[0] != agent_id or current[1] != upstream_scope):
                return False
            self._sessions[session_id] = (agent_id, upstream_scope, now + ttl_seconds)
            return True

    async def validate_mcp_session(
        self, session_id: str, agent_id: int, ttl_seconds: int, upstream_scope: str = "",
    ) -> bool:
        now = time.monotonic()
        with self._lock:
            current = self._sessions.get(session_id)
            if current is None:
                return False
            if current[2] <= now:
                self._sessions.pop(session_id, None)
                return False
            if current[0] != agent_id or current[1] != upstream_scope:
                return False
            self._sessions[session_id] = (agent_id, upstream_scope, now + ttl_seconds)
            return True

    async def claim_requests(self, request_keys: Sequence[str], worker_id: str, lease_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            for key in request_keys:
                claim = self._claims.get(key)
                if claim and claim[1] > now:
                    return False
            for key in request_keys:
                self._claims[key] = (worker_id, now + lease_seconds)
            return True

    async def get_request_owner(self, request_key: str) -> str | None:
        with self._lock:
            claim = self._claims.get(request_key)
            if claim is None or claim[1] <= time.monotonic():
                self._claims.pop(request_key, None)
                return None
            return claim[0]

    async def renew_requests(self, request_keys: Sequence[str], worker_id: str, lease_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            claims = [self._claims.get(key) for key in request_keys]
            if any(claim is None or claim[0] != worker_id or claim[1] <= now for claim in claims):
                return False
            for key in request_keys:
                self._claims[key] = (worker_id, now + lease_seconds)
            return True

    async def release_requests(self, request_keys: Sequence[str], worker_id: str) -> None:
        with self._lock:
            for key in request_keys:
                claim = self._claims.get(key)
                if claim and claim[0] == worker_id:
                    self._claims.pop(key, None)

    async def ensure_event_consumer_group(self, group: str) -> None:
        self._event_stream_queues.setdefault(group, asyncio.Queue())

    async def append_event(self, envelope: dict[str, Any]) -> str:
        self._event_stream_sequence += 1
        entry_id = f"{self._event_stream_sequence}-0"
        for queue in self._event_stream_queues.values():
            queue.put_nowait((entry_id, envelope))
        return entry_id

    async def read_events(
        self, group: str, consumer: str, *, count: int = 20, block_ms: int = 1000,
    ) -> list[tuple[str, dict[str, Any]]]:
        del consumer
        queue = self._event_stream_queues.setdefault(group, asyncio.Queue())
        try:
            first = await asyncio.wait_for(queue.get(), timeout=block_ms / 1000)
        except asyncio.TimeoutError:
            return []
        entries = [first]
        while len(entries) < count:
            try:
                entries.append(queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return entries

    async def acknowledge_events(self, group: str, entry_ids: Sequence[str]) -> None:
        del group, entry_ids

    async def record_event_window(self, key: str, member: str, window_seconds: int) -> tuple[int, bool]:
        now = time.monotonic()
        with self._lock:
            window = self._event_windows[key]
            cutoff = now - max(1, window_seconds)
            while window and window[0][0] <= cutoff:
                window.popleft()
            inserted = not any(existing_member == member for _, existing_member in window)
            if inserted:
                window.append((now, member))
            return len(window), inserted

    async def claim_event_once(self, event_id: str, lease_seconds: int = 120) -> tuple[str | None, str]:
        """Claim an event ID, distinguishing completed replay from in-flight work."""
        key = _stable_key("event-dedup", event_id)
        now = time.monotonic()
        token = uuid.uuid4().hex
        with self._lock:
            existing = self._event_dedup.get(key)
            if existing and existing[1] > now:
                return (None, "done") if existing[0] == "done" else (None, "busy")
            self._event_dedup[key] = (token, now + max(1, lease_seconds))
        return token, "claimed"

    async def finish_event_once(
        self, event_id: str, token: str, *, succeeded: bool, retention_seconds: int = 86400,
    ) -> None:
        key = _stable_key("event-dedup", event_id)
        with self._lock:
            existing = self._event_dedup.get(key)
            if existing is None or existing[0] != token:
                return
            if succeeded:
                self._event_dedup[key] = ("done", time.monotonic() + max(1, retention_seconds))
            else:
                self._event_dedup.pop(key, None)

    async def publish_message(self, message: dict[str, Any]) -> None:
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            subscribers = list(self._subscribers)
        for queue in subscribers:
            queue.put_nowait(payload)

    async def listen(self) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[str] = asyncio.Queue()
        with self._lock:
            self._subscribers.add(queue)
        try:
            while True:
                payload = await queue.get()
                message = json.loads(payload)
                if message.get("kind") == "shutdown":
                    return
                yield message
        finally:
            with self._lock:
                self._subscribers.discard(queue)


_RATE_LIMIT_SCRIPT = """
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local should_consume = ARGV[3] == '1'
local now_ms = tonumber(ARGV[4])
local cutoff = now_ms - window_ms
for i, key in ipairs(KEYS) do
  redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
  if redis.call('ZCARD', key) >= limit then return 0 end
end
if should_consume then
  local member = ARGV[5]
  for i, key in ipairs(KEYS) do
    redis.call('ZADD', key, now_ms, member .. ':' .. i)
    redis.call('PEXPIRE', key, math.max(window_ms * 2, 1000))
  end
end
return 1
"""

_BEGIN_AUTH_ATTEMPT_SCRIPT = """
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local cutoff = now_ms - window_ms
for i, key in ipairs(KEYS) do
  redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
  if redis.call('ZCARD', key) >= limit then return 0 end
end
local token = ARGV[4]
for i, key in ipairs(KEYS) do
  redis.call('ZADD', key, now_ms, token .. ':' .. i)
  redis.call('PEXPIRE', key, math.max(window_ms * 2, 1000))
end
return 1
"""

_FINISH_AUTH_ATTEMPT_SCRIPT = """
for i, key in ipairs(KEYS) do
  redis.call('ZREM', key, ARGV[1] .. ':' .. i)
end
return 1
"""

_BIND_SESSION_SCRIPT = """
local current = redis.call('GET', KEYS[1])
if not current then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
  return 1
end
if current == ARGV[1] then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
  return 1
end
return 0
"""

_VALIDATE_SESSION_SCRIPT = """
local current = redis.call('GET', KEYS[1])
if current and current == ARGV[1] then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
  return 1
end
return 0
"""

_RECORD_EVENT_WINDOW_SCRIPT = """
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local window_ms = math.max(1000, tonumber(ARGV[2]) * 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms - window_ms)
local inserted = redis.call('ZADD', KEYS[1], 'NX', now_ms, ARGV[1])
redis.call('PEXPIRE', KEYS[1], math.max(window_ms * 2, 60000))
return {redis.call('ZCARD', KEYS[1]), inserted and 1 or 0}
"""

_CLAIM_EVENT_ONCE_SCRIPT = """
local current = redis.call('GET', KEYS[1])
if current == 'done' then return 2 end
if current then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 1
"""

_FINISH_EVENT_ONCE_SCRIPT = """
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if ARGV[2] == '1' then
  redis.call('SET', KEYS[1], 'done', 'EX', ARGV[3])
else
  redis.call('DEL', KEYS[1])
end
return 1
"""

_CONSUME_TICKET_SCRIPT = """
local value = redis.call('GET', KEYS[1])
if value then redis.call('DEL', KEYS[1]) end
return value
"""

_CLAIM_REQUESTS_SCRIPT = """
for i, key in ipairs(KEYS) do
  if redis.call('EXISTS', key) == 1 then return 0 end
end
for i, key in ipairs(KEYS) do
  redis.call('SET', key, ARGV[1], 'EX', ARGV[2])
end
return 1
"""

_RENEW_REQUESTS_SCRIPT = """
for i, key in ipairs(KEYS) do
  if redis.call('GET', key) ~= ARGV[1] then return 0 end
end
for i, key in ipairs(KEYS) do
  redis.call('EXPIRE', key, ARGV[2])
end
return 1
"""

_RELEASE_REQUESTS_SCRIPT = """
for i, key in ipairs(KEYS) do
  if redis.call('GET', key) == ARGV[1] then redis.call('DEL', key) end
end
return 1
"""


class RedisSharedState:
    """Redis-backed atomic coordination and cross-worker control/event fanout."""

    is_distributed = True

    def __init__(self, url: str, client: Any | None = None) -> None:
        if client is None:
            from redis.asyncio import Redis

            # RESP2 keeps compatibility with older Windows Redis distributions;
            # Redis Streams capability is detected independently at startup.
            client = Redis.from_url(url, decode_responses=True, socket_connect_timeout=2, protocol=2)
        self._redis = client
        self.worker_id = f"{os.getpid()}-{uuid.uuid4().hex}"
        self._event_streams_available = True

    async def connect(self) -> None:
        try:
            await self._redis.ping()
            self.worker_id = f"{os.getpid()}-{uuid.uuid4().hex}"
        except Exception as exc:
            raise SharedStateUnavailable("Redis is required for shared gateway state") from exc

    async def close(self) -> None:
        await self._redis.aclose()

    async def _eval_rate(self, keys: Sequence[tuple[str, str]], limit: int, window_seconds: int, consume: bool) -> bool:
        redis_keys = [_bucket_key(key) for key in keys]
        try:
            server_time = await self._redis.time()
            now_ms = int(server_time[0]) * 1000 + int(server_time[1]) // 1000
            result = await self._redis.eval(
                _RATE_LIMIT_SCRIPT,
                len(redis_keys),
                *redis_keys,
                limit,
                max(1, int(window_seconds * 1000)),
                "1" if consume else "0",
                now_ms,
                uuid.uuid4().hex,
            )
            return bool(result)
        except Exception as exc:
            raise SharedStateUnavailable("Redis rate-limit operation failed") from exc

    async def is_rate_limited(self, keys: Sequence[tuple[str, str]], limit: int, window_seconds: int) -> bool:
        return not await self._eval_rate(keys, limit, window_seconds, False)

    async def consume_rate_limit(self, keys: Sequence[tuple[str, str]], limit: int, window_seconds: int) -> bool:
        return await self._eval_rate(keys, limit, window_seconds, True)

    async def begin_auth_attempt(
        self, keys: Sequence[tuple[str, str]], limit: int, window_seconds: int,
    ) -> str | None:
        redis_keys = [_bucket_key(key) for key in keys]
        token = uuid.uuid4().hex
        try:
            server_time = await self._redis.time()
            now_ms = int(server_time[0]) * 1000 + int(server_time[1]) // 1000
            result = await self._redis.eval(
                _BEGIN_AUTH_ATTEMPT_SCRIPT,
                len(redis_keys),
                *redis_keys,
                limit,
                max(1, int(window_seconds * 1000)),
                now_ms,
                token,
            )
            return token if result else None
        except Exception as exc:
            raise SharedStateUnavailable("Redis authentication-attempt reservation failed") from exc

    async def finish_auth_attempt(
        self, keys: Sequence[tuple[str, str]], token: str, *, failed: bool,
    ) -> None:
        if failed:
            return
        redis_keys = [_bucket_key(key) for key in keys]
        try:
            await self._redis.eval(_FINISH_AUTH_ATTEMPT_SCRIPT, len(redis_keys), *redis_keys, token)
        except Exception as exc:
            raise SharedStateUnavailable("Redis authentication-attempt release failed") from exc

    async def put_ws_ticket(self, ticket: str, operator_id: int, ttl_seconds: int) -> None:
        try:
            await self._redis.set(_stable_key("ws-ticket", ticket), operator_id, ex=ttl_seconds)
        except Exception as exc:
            raise SharedStateUnavailable("Redis ticket issuance failed") from exc

    async def consume_ws_ticket(self, ticket: str) -> int | None:
        try:
            value = await self._redis.eval(_CONSUME_TICKET_SCRIPT, 1, _stable_key("ws-ticket", ticket))
            return int(value) if value is not None else None
        except Exception as exc:
            raise SharedStateUnavailable("Redis ticket validation failed") from exc

    async def bind_mcp_session(
        self, session_id: str, agent_id: int, ttl_seconds: int, upstream_scope: str = "",
    ) -> bool:
        try:
            return bool(await self._redis.eval(
                _BIND_SESSION_SCRIPT, 1, _stable_key("mcp-session", session_id),
                f"{agent_id}:{upstream_scope}", ttl_seconds,
            ))
        except Exception as exc:
            raise SharedStateUnavailable("Redis session binding failed") from exc

    async def validate_mcp_session(
        self, session_id: str, agent_id: int, ttl_seconds: int, upstream_scope: str = "",
    ) -> bool:
        try:
            return bool(await self._redis.eval(
                _VALIDATE_SESSION_SCRIPT, 1, _stable_key("mcp-session", session_id),
                f"{agent_id}:{upstream_scope}", ttl_seconds,
            ))
        except Exception as exc:
            raise SharedStateUnavailable("Redis session validation failed") from exc

    async def claim_requests(self, request_keys: Sequence[str], worker_id: str, lease_seconds: int) -> bool:
        redis_keys = [_stable_key("request-claim", key) for key in request_keys]
        try:
            return bool(await self._redis.eval(_CLAIM_REQUESTS_SCRIPT, len(redis_keys), *redis_keys, worker_id, lease_seconds))
        except Exception as exc:
            raise SharedStateUnavailable("Redis request claim failed") from exc

    async def get_request_owner(self, request_key: str) -> str | None:
        try:
            return await self._redis.get(_stable_key("request-claim", request_key))
        except Exception as exc:
            raise SharedStateUnavailable("Redis request owner lookup failed") from exc

    async def renew_requests(self, request_keys: Sequence[str], worker_id: str, lease_seconds: int) -> bool:
        redis_keys = [_stable_key("request-claim", key) for key in request_keys]
        try:
            return bool(await self._redis.eval(
                _RENEW_REQUESTS_SCRIPT, len(redis_keys), *redis_keys, worker_id, lease_seconds,
            ))
        except Exception as exc:
            raise SharedStateUnavailable("Redis request lease renewal failed") from exc

    async def release_requests(self, request_keys: Sequence[str], worker_id: str) -> None:
        redis_keys = [_stable_key("request-claim", key) for key in request_keys]
        try:
            await self._redis.eval(_RELEASE_REQUESTS_SCRIPT, len(redis_keys), *redis_keys, worker_id)
        except Exception as exc:
            raise SharedStateUnavailable("Redis request release failed") from exc

    async def ensure_event_consumer_group(self, group: str) -> None:
        if not self._event_streams_available:
            return
        try:
            await self._redis.xgroup_create(EVENT_STREAM, group, id="0-0", mkstream=True)
        except Exception as exc:
            message = str(exc).lower()
            if "busygroup" in message:
                return
            if "unknown command" in message and "xgroup" in message:
                self._event_streams_available = False
                logger.warning(
                    "Redis Streams are unavailable; using the database outbox with Redis pub/sub live delivery"
                )
                return
            raise SharedStateUnavailable("Redis event consumer group setup failed") from exc

    async def append_event(self, envelope: dict[str, Any]) -> str:
        if not self._event_streams_available:
            await self.publish_message({
                "kind": "event",
                "worker_id": self.worker_id,
                "event": envelope if envelope.get("_sentinel_secure_event") else envelope.get("payload", {}),
            })
            return "pubsub"
        try:
            fields = {
                "event_id": str(envelope.get("event_id") or (envelope.get("header") or {}).get("event_id", "")),
                "event_type": str(envelope.get("event_type") or (envelope.get("header") or {}).get("event_type", "")),
                "agent_id": str(envelope.get("agent_id") or (envelope.get("header") or {}).get("agent_id", "")),
                "decision": str(envelope.get("decision") or (envelope.get("header") or {}).get("decision", "")),
                "severity": str(envelope.get("severity") or (envelope.get("header") or {}).get("severity", "info")),
                "schema_version": str(envelope.get("schema_version") or (envelope.get("header") or {}).get("schema_version", "")),
                "occurred_at": str(envelope.get("occurred_at") or (envelope.get("header") or {}).get("occurred_at", "")),
                "topic": str((envelope.get("header") or {}).get("topic", "")),
                "producer_id": str((envelope.get("header") or {}).get("producer_id", "")),
                "security": str((envelope.get("header") or {}).get("security", "plaintext")),
                "payload": json.dumps(
                    envelope if envelope.get("_sentinel_secure_event") else envelope.get("payload", {}),
                    ensure_ascii=False, separators=(",", ":"),
                ),
            }
            return await self._redis.xadd(
                EVENT_STREAM, fields, maxlen=EVENT_STREAM_MAXLEN, approximate=True,
            )
        except Exception as exc:
            raise SharedStateUnavailable("Redis event stream publish failed") from exc

    async def read_events(
        self, group: str, consumer: str, *, count: int = 20, block_ms: int = 1000,
    ) -> list[tuple[str, dict[str, Any]]]:
        if not self._event_streams_available:
            await asyncio.sleep(block_ms / 1000)
            return []
        try:
            reclaimed = await self._redis.xautoclaim(
                EVENT_STREAM, group, consumer, min_idle_time=30_000, start_id="0-0", count=count,
            )
            response = [(EVENT_STREAM, reclaimed[1])] if reclaimed and reclaimed[1] else await self._redis.xreadgroup(
                group, consumer, {EVENT_STREAM: ">"}, count=count, block=block_ms,
            )
            entries: list[tuple[str, dict[str, Any]]] = []
            for _, messages in response:
                for entry_id, fields in messages:
                    try:
                        payload = json.loads(fields.get("payload", "{}"))
                    except (TypeError, json.JSONDecodeError):
                        payload = {}
                    entries.append((entry_id, {
                        "event_id": fields.get("event_id", ""),
                        "event_type": fields.get("event_type", ""),
                        "agent_id": fields.get("agent_id", ""),
                        "decision": fields.get("decision", ""),
                        "severity": fields.get("severity", "info"),
                        "schema_version": fields.get("schema_version", ""),
                        "occurred_at": fields.get("occurred_at", ""),
                        "topic": fields.get("topic", ""),
                        "producer_id": fields.get("producer_id", ""),
                        "security": fields.get("security", "plaintext"),
                        "payload": payload,
                    }))
            return entries
        except Exception as exc:
            raise SharedStateUnavailable("Redis event stream read failed") from exc

    async def acknowledge_events(self, group: str, entry_ids: Sequence[str]) -> None:
        if not self._event_streams_available or not entry_ids:
            return
        try:
            await self._redis.xack(EVENT_STREAM, group, *entry_ids)
        except Exception as exc:
            raise SharedStateUnavailable("Redis event stream acknowledgement failed") from exc

    async def record_event_window(self, key: str, member: str, window_seconds: int) -> tuple[int, bool]:
        try:
            count = await self._redis.eval(
                _RECORD_EVENT_WINDOW_SCRIPT,
                1,
                _stable_key("event-window", key),
                member,
                max(1, int(window_seconds)),
            )
            return int(count[0]), bool(count[1])
        except Exception as exc:
            raise SharedStateUnavailable("Redis event correlation state unavailable") from exc

    async def claim_event_once(self, event_id: str, lease_seconds: int = 120) -> tuple[str | None, str]:
        token = uuid.uuid4().hex
        try:
            result = int(await self._redis.eval(
                _CLAIM_EVENT_ONCE_SCRIPT,
                1,
                _stable_key("event-dedup", event_id),
                token,
                max(1, int(lease_seconds)),
            ))
            if result == 1:
                return token, "claimed"
            return None, "done" if result == 2 else "busy"
        except Exception as exc:
            raise SharedStateUnavailable("Redis event replay guard unavailable") from exc

    async def finish_event_once(
        self, event_id: str, token: str, *, succeeded: bool, retention_seconds: int = 86400,
    ) -> None:
        try:
            await self._redis.eval(
                _FINISH_EVENT_ONCE_SCRIPT,
                1,
                _stable_key("event-dedup", event_id),
                token,
                "1" if succeeded else "0",
                max(1, int(retention_seconds)),
            )
        except Exception as exc:
            raise SharedStateUnavailable("Redis event replay guard update failed") from exc

    async def publish_message(self, message: dict[str, Any]) -> None:
        channel = CONTROL_CHANNEL if message.get("kind") == "cancel" else EVENT_CHANNEL
        try:
            await self._redis.publish(channel, json.dumps(message, ensure_ascii=False, separators=(",", ":")))
        except Exception as exc:
            raise SharedStateUnavailable("Redis message publish failed") from exc

    async def listen(self) -> AsyncIterator[dict[str, Any]]:
        pubsub = self._redis.pubsub()
        try:
            await pubsub.subscribe(EVENT_CHANNEL, CONTROL_CHANNEL)
            async for item in pubsub.listen():
                if item.get("type") != "message":
                    continue
                try:
                    yield json.loads(item["data"])
                except (TypeError, json.JSONDecodeError):
                    continue
        except Exception as exc:
            raise SharedStateUnavailable("Redis message subscription failed") from exc
        finally:
            await pubsub.aclose()


_shared_state: InMemorySharedState | RedisSharedState = InMemorySharedState()


def get_shared_state() -> InMemorySharedState | RedisSharedState:
    return _shared_state


async def configure_shared_state() -> InMemorySharedState | RedisSharedState:
    """Connect the configured backend; production never silently falls back locally."""
    global _shared_state
    redis_url = (
        os.getenv("SENTINEL_REDIS_URL") or os.getenv("SENTINEL_REDIS_REDIS_URL")
        or os.getenv("UPSTASH_REDIS_URL")
        or os.getenv("REDIS_URL", "")
    ).strip()
    production = os.getenv("SENTINEL_ENVIRONMENT", "dev").strip().lower() in {"prod", "production"}
    if redis_url:
        parsed_redis_url = urlsplit(redis_url)
        require_tls = os.getenv(
            "SENTINEL_REDIS_REQUIRE_TLS", "true" if production else "false",
        ).strip().lower() in {"1", "true", "yes", "on"}
        if require_tls and parsed_redis_url.scheme != "rediss":
            raise RuntimeError("Redis event transport requires a rediss:// URL when TLS is enforced")
        if production and not (parsed_redis_url.username and parsed_redis_url.password):
            raise RuntimeError("Production Redis requires an ACL username and password")
        state: InMemorySharedState | RedisSharedState = RedisSharedState(redis_url)
    elif production:
        raise RuntimeError("SENTINEL_REDIS_URL is required in production")
    else:
        state = InMemorySharedState()
    await state.connect()
    previous = _shared_state
    _shared_state = state
    if previous is not state:
        await previous.close()
    return state


async def close_shared_state() -> None:
    await _shared_state.close()
