"""Transactional outbox publisher and Redis Streams event consumers."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import socket
from datetime import datetime, timezone
from datetime import timedelta
from typing import Any, Awaitable, Callable

from sqlalchemy import or_
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from time_utils import utcnow

logger = logging.getLogger(__name__)

EVENT_CONSUMER_GROUP = os.getenv("SENTINEL_EVENT_CONSUMER_GROUP", "sentinel-live-dashboard-v1")
OUTBOX_POLL_SECONDS = max(0.1, float(os.getenv("SENTINEL_OUTBOX_POLL_SECONDS", "0.5")))
OUTBOX_BATCH_SIZE = max(1, min(100, int(os.getenv("SENTINEL_OUTBOX_BATCH_SIZE", "25"))))
OUTBOX_LEASE_SECONDS = max(10, int(os.getenv("SENTINEL_OUTBOX_LEASE_SECONDS", "60")))
STREAM_BLOCK_MS = max(100, int(os.getenv("SENTINEL_EVENT_STREAM_BLOCK_MS", "1000")))
STREAM_BATCH_SIZE = max(1, min(100, int(os.getenv("SENTINEL_EVENT_STREAM_BATCH_SIZE", "25"))))
OUTBOX_MAX_ATTEMPTS = max(1, int(os.getenv("SENTINEL_OUTBOX_MAX_ATTEMPTS", "12")))
_WORKER_NAME = f"{socket.gethostname()}-{os.getpid()}"
_SECURE_EVENT_MARKER = "sentinel-e2e-v1"
_EVENT_TOPIC = os.getenv("SENTINEL_EVENT_TOPIC", "gateway.events")
_EVENT_PRODUCER_ID = os.getenv("SENTINEL_EVENT_PRODUCER_ID", "sentinel-gateway")
CEP_AGENT_BLOCK_THRESHOLD = max(2, int(os.getenv("SENTINEL_CEP_AGENT_BLOCK_THRESHOLD", "5")))
CEP_AGENT_BLOCK_WINDOW_SECONDS = max(30, int(os.getenv("SENTINEL_CEP_AGENT_BLOCK_WINDOW_SECONDS", "120")))
CEP_RULE_AGENT_THRESHOLD = max(2, int(os.getenv("SENTINEL_CEP_RULE_AGENT_THRESHOLD", "3")))
CEP_RULE_AGENT_WINDOW_SECONDS = max(60, int(os.getenv("SENTINEL_CEP_RULE_AGENT_WINDOW_SECONDS", "300")))
CEP_FANOUT_AGENT_THRESHOLD = max(2, int(os.getenv("SENTINEL_CEP_FANOUT_AGENT_THRESHOLD", "3")))
CEP_FANOUT_WINDOW_SECONDS = max(60, int(os.getenv("SENTINEL_CEP_FANOUT_WINDOW_SECONDS", "300")))
EVENT_REPLAY_RETENTION_SECONDS = max(60, int(os.getenv("SENTINEL_EVENT_REPLAY_RETENTION_SECONDS", "86400")))


def _event_key(env_name: str, expected_bytes: int) -> bytes | None:
    configured = os.getenv(env_name, "").strip()
    if not configured:
        return None
    try:
        value = base64.b64decode(configured, validate=True)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"{env_name} must be base64 encoded") from exc
    if len(value) != expected_bytes:
        raise RuntimeError(f"{env_name} must decode to exactly {expected_bytes} bytes")
    return value


def _event_signer() -> Ed25519PrivateKey | None:
    seed = _event_key("SENTINEL_EVENT_SIGNING_PRIVATE_KEY", 32)
    return Ed25519PrivateKey.from_private_bytes(seed) if seed else None


def _event_verifier() -> Ed25519PublicKey | None:
    public_bytes = _event_key("SENTINEL_EVENT_SIGNING_PUBLIC_KEY", 32)
    if public_bytes:
        return Ed25519PublicKey.from_public_bytes(public_bytes)
    signer = _event_signer()
    return signer.public_key() if signer else None


def _event_public_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def validate_event_security_configuration() -> None:
    """Fail at startup for partial or mismatched publisher/subscriber key configuration."""
    encryption_key = _event_key("SENTINEL_EVENT_ENCRYPTION_KEY", 32)
    private_seed = _event_key("SENTINEL_EVENT_SIGNING_PRIVATE_KEY", 32)
    public_bytes = _event_key("SENTINEL_EVENT_SIGNING_PUBLIC_KEY", 32)
    if encryption_key is None:
        transports = {
            value.strip().lower()
            for value in os.getenv("SENTINEL_EVENT_TRANSPORTS", "redis").split(",")
            if value.strip()
        }
        production = os.getenv("SENTINEL_ENVIRONMENT", "dev").strip().lower() in {"prod", "production"}
        if production or transports.intersection({"mqtt", "kafka"}):
            raise RuntimeError("Event encryption and signing keys are required in production and external broker mode")
        if private_seed is not None or public_bytes is not None:
            raise RuntimeError("Event signing keys require SENTINEL_EVENT_ENCRYPTION_KEY")
        return
    if private_seed is None:
        raise RuntimeError("SENTINEL_EVENT_SIGNING_PRIVATE_KEY is required when event encryption is enabled")
    derived_public = _event_public_bytes(Ed25519PrivateKey.from_private_bytes(private_seed).public_key())
    if public_bytes is not None and public_bytes != derived_public:
        raise RuntimeError("SENTINEL_EVENT_SIGNING_PUBLIC_KEY does not match the configured private key")


def _routing_header(message: dict[str, Any], encryption_key: bytes, public_key: Ed25519PublicKey) -> dict[str, Any]:
    data = message.get("data") if isinstance(message.get("data"), dict) else {}
    header: dict[str, Any] = {
        "security": _SECURE_EVENT_MARKER,
        "topic": _EVENT_TOPIC,
        "producer_id": _EVENT_PRODUCER_ID,
        "key_id": hashlib.sha256(encryption_key).hexdigest()[:16],
        "signing_key_id": hashlib.sha256(_event_public_bytes(public_key)).hexdigest()[:16],
    }
    for key in ("event_id", "event_type", "schema_version", "occurred_at", "agent_id", "decision", "severity"):
        value = message.get(key, data.get(key))
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            header[key] = value
    if "event_type" not in header and isinstance(message.get("type"), str):
        header["event_type"] = message["type"]
    return header


def protect_broker_message(message: dict[str, Any]) -> dict[str, Any]:
    """Encrypt a message for topic subscribers and authenticate its producer identity."""
    encryption_key = _event_key("SENTINEL_EVENT_ENCRYPTION_KEY", 32)
    if encryption_key is None:
        return message
    signer = _event_signer()
    if signer is None:
        raise RuntimeError("SENTINEL_EVENT_SIGNING_PRIVATE_KEY is required when event encryption is enabled")
    header = _routing_header(message, encryption_key, signer.public_key())
    aad = _canonical_json(header)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(encryption_key).encrypt(nonce, _canonical_json(message), aad)
    signature = signer.sign(aad + nonce + ciphertext)
    return {
        "_sentinel_secure_event": _SECURE_EVENT_MARKER,
        "header": header,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def open_broker_message(
    message: dict[str, Any], *, expected_routing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify the producer signature and decrypt a topic message for an authorized subscriber."""
    encrypted = message.get("_sentinel_secure_event") == _SECURE_EVENT_MARKER
    if not encrypted:
        if os.getenv("SENTINEL_EVENT_ENCRYPTION_KEY", "").strip():
            raise RuntimeError("Refusing an unencrypted event while event encryption is enabled")
        return message
    encryption_key = _event_key("SENTINEL_EVENT_ENCRYPTION_KEY", 32)
    verifier = _event_verifier()
    if encryption_key is None or verifier is None:
        raise RuntimeError("Subscriber event encryption and signing verification keys are required")
    header = message.get("header")
    if not isinstance(header, dict) or header.get("security") != _SECURE_EVENT_MARKER:
        raise RuntimeError("Invalid secure event header")
    if expected_routing:
        for key in (
            "event_id", "event_type", "schema_version", "occurred_at", "agent_id",
            "decision", "severity", "topic", "producer_id", "security",
        ):
            outer_value = expected_routing.get(key)
            if outer_value not in (None, "") and str(outer_value) != str(header.get(key, "")):
                raise RuntimeError(f"Broker routing metadata mismatch for {key}")
    if header.get("key_id") != hashlib.sha256(encryption_key).hexdigest()[:16]:
        raise RuntimeError("Secure event uses an unknown encryption key")
    public_bytes = _event_public_bytes(verifier)
    if header.get("signing_key_id") != hashlib.sha256(public_bytes).hexdigest()[:16]:
        raise RuntimeError("Secure event uses an unknown signing key")
    try:
        nonce = base64.b64decode(message["nonce"], validate=True)
        ciphertext = base64.b64decode(message["ciphertext"], validate=True)
        signature = base64.b64decode(message["signature"], validate=True)
        aad = _canonical_json(header)
        verifier.verify(signature, aad + nonce + ciphertext)
        plaintext = AESGCM(encryption_key).decrypt(nonce, ciphertext, aad)
        decoded = json.loads(plaintext)
    except (KeyError, ValueError, TypeError, InvalidSignature, InvalidTag, json.JSONDecodeError) as exc:
        raise RuntimeError("Secure event authentication or decryption failed") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("Secure event payload must be a JSON object")
    return decoded


async def correlate_security_event(state: Any, event: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect behavioral drift, suspicious fan-out, bursts, and rule campaigns."""
    if event.get("type") != "mcp_event" or not isinstance(event.get("data"), dict):
        return []
    data = event["data"]
    decision = data.get("decision")
    anomaly = data.get("ml_anomaly") is True
    if decision not in {"block", "flag"} and not anomaly:
        return []
    event_id = str(data.get("event_id") or "")
    agent_id = data.get("agent_id")
    if not event_id or not isinstance(agent_id, int):
        return []

    signals: list[tuple[str, str, str]] = []
    if anomaly:
        behavior_context = "an allowed event" if decision == "allow" else f"a {decision} event"
        signals.append((
            "CEP-BEHAVIORAL-DRIFT",
            f"Agent {agent_id} produced {behavior_context} outside its learned behavior baseline",
            "high",
        ))
        tool_name = str(data.get("tool_name") or "").lower()
        sensitive_actions = ("publish", "send", "execute", "run", "delete", "transfer", "write", "deploy", "admin")
        if any(action in tool_name for action in sensitive_actions):
            signals.append((
                "CEP-ANOMALOUS-SENSITIVE-ACTION",
                f"Behaviorally unusual event attempted sensitive action tool {tool_name[:80]}",
                "high",
            ))

    if decision in {"block", "flag"}:
        count, inserted = await state.record_event_window(
            f"agent-blocks:{agent_id}", event_id, CEP_AGENT_BLOCK_WINDOW_SECONDS,
        )
        if inserted and count == CEP_AGENT_BLOCK_THRESHOLD:
            signals.append((
                "CEP-AGENT-BLOCK-BURST",
                f"Agent {agent_id} generated {count} blocked or flagged requests in {CEP_AGENT_BLOCK_WINDOW_SECONDS} seconds",
                "high",
            ))

    # A payload fingerprint repeated across independently authenticated agents
    # is a useful collusion/fan-out signal even when each request is schema-valid.
    fingerprint = data.get("payload_hash")
    if isinstance(fingerprint, str) and len(fingerprint) == 64 and (anomaly or decision in {"block", "flag"}):
        count, inserted = await state.record_event_window(
            f"publisher-fanout:{fingerprint}", str(agent_id), CEP_FANOUT_WINDOW_SECONDS,
        )
        if inserted and count == CEP_FANOUT_AGENT_THRESHOLD:
            signals.append((
                "CEP-PUBLISHER-FANOUT-COLLUSION",
                f"The same suspicious payload fingerprint appeared from {count} agents within {CEP_FANOUT_WINDOW_SECONDS} seconds",
                "critical",
            ))

    matched_rules = data.get("matched_rule_ids")
    if decision in {"block", "flag"} and isinstance(matched_rules, list):
        for rule_id in dict.fromkeys(value for value in matched_rules[:8] if isinstance(value, str)):
            count, inserted = await state.record_event_window(
                f"rule-agents:{rule_id}", str(agent_id), CEP_RULE_AGENT_WINDOW_SECONDS,
            )
            if inserted and count == CEP_RULE_AGENT_THRESHOLD:
                signals.append((
                    "CEP-CROSS-AGENT-RULE-CAMPAIGN",
                    f"Rule {rule_id} matched across {count} agents in {CEP_RULE_AGENT_WINDOW_SECONDS} seconds",
                    "high",
                ))

    occurred_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    results = []
    for rule_id, summary, severity in signals:
        correlation_id = hashlib.sha256(f"{rule_id}:{event_id}".encode("utf-8")).hexdigest()[:32]
        results.append({
            "type": "security_correlation",
            "data": {
                "event_id": f"cep-{correlation_id}",
                "timestamp": occurred_at,
                "agent_id": agent_id,
                "agent_name": "Gateway event correlation",
                "method": "security/correlation",
                "tool_name": data.get("tool_name"),
                "environment": data.get("environment"),
                "decision": "flag",
                "decision_reason": summary,
                "decision_source": "cep",
                "matched_rule_ids": [rule_id],
                "rule_risk_score": 0.95,
                "ml_anomaly": False,
                "severity": severity,
                "correlation_window_seconds": {
                    "CEP-AGENT-BLOCK-BURST": CEP_AGENT_BLOCK_WINDOW_SECONDS,
                    "CEP-CROSS-AGENT-RULE-CAMPAIGN": CEP_RULE_AGENT_WINDOW_SECONDS,
                    "CEP-PUBLISHER-FANOUT-COLLUSION": CEP_FANOUT_WINDOW_SECONDS,
                }.get(rule_id, CEP_RULE_AGENT_WINDOW_SECONDS),
                "trigger_event_id": event_id,
            },
        })
    return results


def update_outbox_payload(event_id: str, payload: dict[str, Any]) -> bool:
    """Persist the final sanitized live-feed envelope after synchronous enrichment."""
    from database import MCPEventOutbox, SessionLocal

    db = SessionLocal()
    try:
        updated = db.query(MCPEventOutbox).filter(
            MCPEventOutbox.event_id == event_id,
            MCPEventOutbox.status == "pending",
        ).update({MCPEventOutbox.payload_json: json.dumps(payload, ensure_ascii=False)})
        db.commit()
        return bool(updated)
    except Exception:
        db.rollback()
        logger.exception("Could not update outbox payload event_id=%s", event_id)
        return False
    finally:
        db.close()


def _claim_outbox_batch() -> list[dict[str, Any]]:
    """Lease pending rows atomically; expired leases are recoverable after crashes."""
    from database import MCPEventOutbox, SessionLocal

    now = utcnow()
    expired_lease = or_(
        MCPEventOutbox.locked_until.is_(None),
        MCPEventOutbox.locked_until <= now,
    )
    eligible = or_(
        MCPEventOutbox.status == "pending",
        (MCPEventOutbox.status == "publishing") & expired_lease,
    )
    db = SessionLocal()
    claimed: list[dict[str, Any]] = []
    try:
        rows = (
            db.query(MCPEventOutbox)
            .filter(eligible, MCPEventOutbox.next_attempt_at <= now)
            .order_by(MCPEventOutbox.id.asc())
            .limit(OUTBOX_BATCH_SIZE)
            .all()
        )
        for row in rows:
            updated = (
                db.query(MCPEventOutbox)
                .filter(MCPEventOutbox.id == row.id, eligible, MCPEventOutbox.next_attempt_at <= now)
                .update({
                    MCPEventOutbox.status: "publishing",
                    MCPEventOutbox.locked_by: _WORKER_NAME,
                    MCPEventOutbox.locked_until: now + timedelta(seconds=OUTBOX_LEASE_SECONDS),
                    MCPEventOutbox.attempts: MCPEventOutbox.attempts + 1,
                }, synchronize_session=False)
            )
            if updated:
                claimed.append({
                    "id": row.id,
                    "event_id": row.event_id,
                    "event_type": row.event_type,
                    "schema_version": row.schema_version,
                    "occurred_at": row.occurred_at.isoformat() + "Z",
                    "agent_id": row.agent_id,
                    "decision": row.decision,
                    "severity": row.severity,
                    "payload": json.loads(row.payload_json),
                    "attempts": (row.attempts or 0) + 1,
                })
        db.commit()
        return claimed
    except Exception:
        db.rollback()
        logger.exception("Could not claim MCP event outbox rows")
        return []
    finally:
        db.close()


def _finish_outbox(event_id: str, *, error: str | None = None, attempts: int = 1) -> None:
    from database import MCPEventOutbox, SessionLocal

    db = SessionLocal()
    try:
        row = db.query(MCPEventOutbox).filter_by(event_id=event_id).first()
        if row is None:
            return
        row.locked_by = None
        row.locked_until = None
        row.last_error = error[:200] if error else None
        if error:
            if attempts >= OUTBOX_MAX_ATTEMPTS:
                row.status = "dead_letter"
                row.dead_lettered_at = utcnow()
                logger.error("MCP outbox event dead-lettered event_id=%s", event_id)
            else:
                row.status = "pending"
                row.next_attempt_at = utcnow() + timedelta(seconds=min(300, 2 ** min(attempts, 8)))
        else:
            row.status = "published"
            row.published_at = utcnow()
            row.next_attempt_at = utcnow()
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not update MCP outbox status event_id=%s", event_id)
    finally:
        db.close()


async def run_outbox_publisher() -> None:
    """Move committed outbox records to the broker with retry/backoff."""
    from event_transports import publish_event
    from shared_state import SharedStateUnavailable

    while True:
        batch = await asyncio.to_thread(_claim_outbox_batch)
        if not batch:
            await asyncio.sleep(OUTBOX_POLL_SECONDS)
            continue
        for row in batch:
            envelope = {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "schema_version": row["schema_version"],
                "occurred_at": row["occurred_at"],
                "agent_id": row["agent_id"],
                "decision": row["decision"],
                "severity": row["severity"],
                "payload": row["payload"],
            }
            try:
                await publish_event(envelope)
                await asyncio.to_thread(_finish_outbox, row["event_id"])
            except (SharedStateUnavailable, Exception) as exc:
                logger.warning(
                    "MCP event publish deferred event_id=%s error_type=%s",
                    row["event_id"], type(exc).__name__,
                )
                await asyncio.to_thread(
                    _finish_outbox,
                    row["event_id"],
                    error=type(exc).__name__,
                    attempts=row["attempts"],
                )


async def run_event_consumer(
    handler: Callable[[dict[str, Any]], Awaitable[None]],
) -> None:
    """Consume stream entries; only acknowledge after downstream handling succeeds."""
    from shared_state import SharedStateUnavailable, get_shared_state

    while True:
        state = get_shared_state()
        try:
            await state.ensure_event_consumer_group(EVENT_CONSUMER_GROUP)
            entries = await state.read_events(
                EVENT_CONSUMER_GROUP,
                f"{_WORKER_NAME}-{state.worker_id}",
                count=STREAM_BATCH_SIZE,
                block_ms=STREAM_BLOCK_MS,
            )
            for entry_id, envelope in entries:
                try:
                    payload = envelope.get("payload") if isinstance(envelope.get("payload"), dict) else envelope
                    decoded = open_broker_message(
                        payload,
                        expected_routing=envelope if payload is not envelope else None,
                    ) if isinstance(payload, dict) else {}
                    # Stream entries wrap the dashboard event in the durable outbox envelope.
                    event = decoded.get("payload") if isinstance(decoded.get("payload"), dict) else decoded
                    if isinstance(event, dict):
                        event_data = event.get("data") if isinstance(event.get("data"), dict) else {}
                        event_id = str(event_data.get("event_id") or event.get("event_id") or "")
                        if not event_id:
                            logger.error("Discarding broker event without a stable event_id stream_id=%s", entry_id)
                            await state.acknowledge_events(EVENT_CONSUMER_GROUP, [entry_id])
                            continue
                        replay_key = f"{EVENT_CONSUMER_GROUP}:{event_id}"
                        claim, claim_status = await state.claim_event_once(replay_key)
                        if claim_status == "done":
                            await state.acknowledge_events(EVENT_CONSUMER_GROUP, [entry_id])
                            continue
                        if claim_status == "busy" or claim is None:
                            # Keep this stream entry pending; a completed duplicate
                            # will be acked on reclaim, while a failed owner can expire.
                            continue
                        try:
                            from event_features import add_observable_features

                            await add_observable_features(state, event, envelope, entry_id)
                            await handler(event)
                            for correlation in await correlate_security_event(state, event):
                                await handler(correlation)
                        except BaseException:
                            await asyncio.shield(state.finish_event_once(
                                replay_key, claim, succeeded=False,
                            ))
                            raise
                        await state.finish_event_once(
                            replay_key,
                            claim,
                            succeeded=True,
                            retention_seconds=EVENT_REPLAY_RETENTION_SECONDS,
                        )
                    await state.acknowledge_events(EVENT_CONSUMER_GROUP, [entry_id])
                except Exception:
                    logger.exception("MCP event consumer failed event_id=%s", envelope.get("event_id"))
        except asyncio.CancelledError:
            raise
        except (SharedStateUnavailable, Exception):
            logger.exception("MCP event consumer unavailable; reconnecting")
            await asyncio.sleep(1)
