import asyncio

import pytest
from fakeredis import FakeServer
from fakeredis.aioredis import FakeRedis

from shared_state import RedisSharedState


@pytest.fixture
async def redis_workers():
    server = FakeServer()
    first_client = FakeRedis(server=server, decode_responses=True)
    second_client = FakeRedis(server=server, decode_responses=True)
    first = RedisSharedState("redis://shared-test", client=first_client)
    second = RedisSharedState("redis://shared-test", client=second_client)
    await first.connect()
    await second.connect()
    try:
        yield first, second
    finally:
        await first.close()
        await second.close()


@pytest.mark.asyncio
async def test_sliding_window_rate_limit_is_atomic_across_workers(redis_workers):
    first, second = redis_workers
    keys = [("ip", "127.0.0.1"), ("agent", "17")]

    results = await asyncio.gather(*(
        state.consume_rate_limit(keys, limit=1, window_seconds=60)
        for state in (first, second)
    ))

    assert sorted(results) == [False, True]
    assert await first.is_rate_limited(keys, limit=1, window_seconds=60)


@pytest.mark.asyncio
async def test_successful_auth_reservation_is_released_but_failure_counts(redis_workers):
    first, second = redis_workers
    keys = [("ip", "127.0.0.1"), ("key", "key-prefix")]

    reservation = await first.begin_auth_attempt(keys, limit=1, window_seconds=60)
    assert reservation is not None
    assert await second.begin_auth_attempt(keys, limit=1, window_seconds=60) is None
    await first.finish_auth_attempt(keys, reservation, failed=False)

    failed_reservation = await second.begin_auth_attempt(keys, limit=1, window_seconds=60)
    assert failed_reservation is not None
    await second.finish_auth_attempt(keys, failed_reservation, failed=True)
    assert await first.begin_auth_attempt(keys, limit=1, window_seconds=60) is None


@pytest.mark.asyncio
async def test_websocket_ticket_is_one_use_across_workers(redis_workers):
    first, second = redis_workers
    await first.put_ws_ticket("ticket-value", operator_id=42, ttl_seconds=30)

    assert await second.consume_ws_ticket("ticket-value") == 42
    assert await first.consume_ws_ticket("ticket-value") is None


@pytest.mark.asyncio
async def test_session_binding_is_exclusive_and_owner_validation_refreshes_ttl(redis_workers):
    first, second = redis_workers

    results = await asyncio.gather(
        first.bind_mcp_session("session-1", agent_id=1, ttl_seconds=60),
        second.bind_mcp_session("session-1", agent_id=2, ttl_seconds=60),
    )

    assert sorted(results) == [False, True]
    owner = 1 if results[0] else 2
    owner_state = first if owner == 1 else second
    other_state = second if owner == 1 else first
    assert await owner_state.validate_mcp_session("session-1", owner, ttl_seconds=60)
    assert not await other_state.validate_mcp_session("session-1", 999, ttl_seconds=60)


@pytest.mark.asyncio
async def test_request_claims_are_shared_renewable_and_owner_released(redis_workers):
    first, second = redis_workers
    request_keys = ["17:session-1:1", "17:session-1:2"]

    assert await first.claim_requests(request_keys, first.worker_id, lease_seconds=30)
    assert not await second.claim_requests(request_keys, second.worker_id, lease_seconds=30)
    assert await second.get_request_owner(request_keys[0]) == first.worker_id
    assert await first.renew_requests(request_keys, first.worker_id, lease_seconds=30)
    assert not await second.renew_requests(request_keys, second.worker_id, lease_seconds=30)

    await first.release_requests(request_keys, first.worker_id)
    assert await second.claim_requests(request_keys, second.worker_id, lease_seconds=30)


@pytest.mark.asyncio
async def test_pubsub_delivers_sanitized_gateway_message_to_other_worker(redis_workers):
    first, second = redis_workers
    listener = second.listen()
    next_message = asyncio.create_task(anext(listener))
    await asyncio.sleep(0.05)
    await first.publish_message({"kind": "event", "worker_id": first.worker_id, "event": {"type": "mcp_event"}})

    message = await asyncio.wait_for(next_message, timeout=2)
    assert message == {"kind": "event", "worker_id": first.worker_id, "event": {"type": "mcp_event"}}
    await listener.aclose()


@pytest.mark.asyncio
async def test_production_requires_configured_redis(monkeypatch):
    import shared_state

    previous = shared_state.get_shared_state()
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "production")
    monkeypatch.delenv("SENTINEL_REDIS_URL", raising=False)
    try:
        with pytest.raises(RuntimeError, match="SENTINEL_REDIS_URL is required"):
            await shared_state.configure_shared_state()
    finally:
        shared_state._shared_state = previous
