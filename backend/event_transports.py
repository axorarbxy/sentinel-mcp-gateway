"""Optional MQTT and Kafka fan-out adapters for the durable gateway event spine."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
import threading
from typing import Any
from urllib.parse import urlsplit

from event_pipeline import protect_broker_message

logger = logging.getLogger(__name__)
_KAFKA_PRODUCER = None
_KAFKA_LOCK = threading.Lock()


def configured_transports() -> tuple[str, ...]:
    values = tuple(dict.fromkeys(
        value.strip().lower()
        for value in os.getenv("SENTINEL_EVENT_TRANSPORTS", "redis").split(",")
        if value.strip()
    ))
    if not values or set(values) - {"redis", "mqtt", "kafka"}:
        raise RuntimeError("SENTINEL_EVENT_TRANSPORTS must contain redis, mqtt, and/or kafka")
    if "redis" not in values:
        raise RuntimeError("Redis is required for the gateway's durable event and CEP pipeline")
    return values


def validate_transport_configuration() -> None:
    transports = configured_transports()
    production = os.getenv("SENTINEL_ENVIRONMENT", "dev").strip().lower() in {"prod", "production"}
    if "mqtt" in transports:
        if importlib.util.find_spec("paho") is None or importlib.util.find_spec("paho.mqtt") is None:
            raise RuntimeError("MQTT is enabled but paho-mqtt is missing; install requirements-event-transports.txt")
        url = urlsplit(os.getenv("SENTINEL_MQTT_URL", ""))
        if url.scheme not in {"mqtt", "mqtts"} or not url.hostname:
            raise RuntimeError("MQTT fan-out requires SENTINEL_MQTT_URL using mqtt:// or mqtts://")
        if production and (url.scheme != "mqtts" or not os.getenv("SENTINEL_MQTT_USERNAME") or not os.getenv("SENTINEL_MQTT_PASSWORD")):
            raise RuntimeError("Production MQTT requires mqtts:// and broker credentials")
    if "kafka" in transports:
        if importlib.util.find_spec("kafka") is None:
            raise RuntimeError("Kafka is enabled but kafka-python is missing; install requirements-event-transports.txt")
        if not os.getenv("SENTINEL_KAFKA_BOOTSTRAP_SERVERS", "").strip():
            raise RuntimeError("Kafka fan-out requires SENTINEL_KAFKA_BOOTSTRAP_SERVERS")
        if production and (
            os.getenv("SENTINEL_KAFKA_SECURITY_PROTOCOL", "PLAINTEXT").upper() != "SASL_SSL"
            or not os.getenv("SENTINEL_KAFKA_USERNAME")
            or not os.getenv("SENTINEL_KAFKA_PASSWORD")
        ):
            raise RuntimeError("Production Kafka requires SASL_SSL and broker credentials")


def _publish_mqtt(payload: bytes) -> None:
    from paho.mqtt import publish

    parsed = urlsplit(os.environ["SENTINEL_MQTT_URL"])
    auth = None
    username = os.getenv("SENTINEL_MQTT_USERNAME", "")
    password = os.getenv("SENTINEL_MQTT_PASSWORD", "")
    if username or password:
        auth = {"username": username, "password": password}
    tls = None
    if parsed.scheme == "mqtts":
        tls = {}
        ca_file = os.getenv("SENTINEL_MQTT_TLS_CAFILE", "").strip()
        if ca_file:
            tls["ca_certs"] = ca_file
    publish.single(
        os.getenv("SENTINEL_MQTT_TOPIC", "sentinel/mcp/events"),
        payload=payload,
        qos=1,
        hostname=parsed.hostname,
        port=parsed.port or (8883 if parsed.scheme == "mqtts" else 1883),
        auth=auth,
        tls=tls,
        keepalive=30,
    )


def _get_kafka_producer():
    global _KAFKA_PRODUCER
    if _KAFKA_PRODUCER is not None:
        return _KAFKA_PRODUCER
    with _KAFKA_LOCK:
        if _KAFKA_PRODUCER is not None:
            return _KAFKA_PRODUCER
        from kafka import KafkaProducer

        config: dict[str, Any] = {
            "bootstrap_servers": [
                value.strip()
                for value in os.environ["SENTINEL_KAFKA_BOOTSTRAP_SERVERS"].split(",")
                if value.strip()
            ],
            "security_protocol": os.getenv("SENTINEL_KAFKA_SECURITY_PROTOCOL", "PLAINTEXT").upper(),
            "acks": "all",
            "retries": 5,
            "max_in_flight_requests_per_connection": 1,
            "client_id": os.getenv("SENTINEL_KAFKA_CLIENT_ID", "sentinel-mcp-gateway"),
        }
        mechanism = os.getenv("SENTINEL_KAFKA_SASL_MECHANISM", "PLAIN").upper()
        if config["security_protocol"].startswith("SASL_"):
            config.update({
                "sasl_mechanism": mechanism,
                "sasl_plain_username": os.getenv("SENTINEL_KAFKA_USERNAME", ""),
                "sasl_plain_password": os.getenv("SENTINEL_KAFKA_PASSWORD", ""),
            })
        ca_file = os.getenv("SENTINEL_KAFKA_SSL_CAFILE", "").strip()
        if ca_file:
            config["ssl_cafile"] = ca_file
        _KAFKA_PRODUCER = KafkaProducer(**config)
        return _KAFKA_PRODUCER


def _publish_kafka(payload: bytes, event_id: str) -> None:
    producer = _get_kafka_producer()
    producer.send(
        os.getenv("SENTINEL_KAFKA_TOPIC", "sentinel-mcp-events"),
        key=event_id.encode("utf-8"),
        value=payload,
        headers=[("content-type", b"application/json")],
    ).get(timeout=15)


async def publish_event(envelope: dict[str, Any]) -> None:
    """Publish an idempotency-keyed, protected envelope to configured integrations."""
    from shared_state import get_shared_state

    sinks = configured_transports()
    protected = protect_broker_message(envelope)
    payload = json.dumps(protected, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    event_id = str(envelope.get("event_id", ""))
    if "redis" in sinks:
        await get_shared_state().append_event(protected)
    if "mqtt" in sinks:
        await asyncio.to_thread(_publish_mqtt, payload)
    if "kafka" in sinks:
        await asyncio.to_thread(_publish_kafka, payload, event_id)


async def close_event_transports() -> None:
    global _KAFKA_PRODUCER
    producer = _KAFKA_PRODUCER
    _KAFKA_PRODUCER = None
    if producer is not None:
        await asyncio.to_thread(producer.close, timeout=10)
