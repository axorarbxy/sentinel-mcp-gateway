"""Ephemeral gateway coordination with an in-memory dev adapter and Redis backend."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Sequence
from typing import Any


REDIS_PREFIX = os.getenv("SENTINEL_REDIS_KEY_PREFIX", "sentinel")
EVENT_CHANNEL = f"{REDIS_PREFIX}:gateway:events"
CONTROL_CHANNEL = f"{REDIS_PREFIX}:gateway:control"
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
        self._sessions: dict[str, tuple[int, float]] = {}
        self._claims: dict[str, tuple[str, float]] = {}
        self._subscribers: set[asyncio.Queue[str]] = set()

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

    async def bind_mcp_session(self, session_id: str, agent_id: int, ttl_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            current = self._sessions.get(session_id)
            if current and current[1] > now and current[0] != agent_id:
                return False
            self._sessions[session_id] = (agent_id, now + ttl_seconds)
            return True

    async def validate_mcp_session(self, session_id: str, agent_id: int, ttl_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            current = self._sessions.get(session_id)
            if current is None or current[1] <= now or current[0] != agent_id:
                self._sessions.pop(session_id, None)
                return False
            self._sessions[session_id] = (agent_id, now + ttl_seconds)
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
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local cutoff = now_ms - window_ms
for i, key in ipairs(KEYS) do
  redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
  if redis.call('ZCARD', key) >= limit then return 0 end
end
if should_consume then
  local member = ARGV[4]
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
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local cutoff = now_ms - window_ms
for i, key in ipairs(KEYS) do
  redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
  if redis.call('ZCARD', key) >= limit then return 0 end
end
local token = ARGV[3]
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

            client = Redis.from_url(url, decode_responses=True, socket_connect_timeout=2)
        self._redis = client
        self.worker_id = f"{os.getpid()}-{uuid.uuid4().hex}"

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
            result = await self._redis.eval(
                _RATE_LIMIT_SCRIPT,
                len(redis_keys),
                *redis_keys,
                limit,
                max(1, int(window_seconds * 1000)),
                "1" if consume else "0",
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
            result = await self._redis.eval(
                _BEGIN_AUTH_ATTEMPT_SCRIPT,
                len(redis_keys),
                *redis_keys,
                limit,
                max(1, int(window_seconds * 1000)),
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

    async def bind_mcp_session(self, session_id: str, agent_id: int, ttl_seconds: int) -> bool:
        try:
            return bool(await self._redis.eval(
                _BIND_SESSION_SCRIPT, 1, _stable_key("mcp-session", session_id), agent_id, ttl_seconds,
            ))
        except Exception as exc:
            raise SharedStateUnavailable("Redis session binding failed") from exc

    async def validate_mcp_session(self, session_id: str, agent_id: int, ttl_seconds: int) -> bool:
        try:
            return bool(await self._redis.eval(
                _VALIDATE_SESSION_SCRIPT, 1, _stable_key("mcp-session", session_id), agent_id, ttl_seconds,
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
    redis_url = os.getenv("SENTINEL_REDIS_URL", "").strip()
    production = os.getenv("SENTINEL_ENVIRONMENT", "dev").strip().lower() in {"prod", "production"}
    if redis_url:
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
