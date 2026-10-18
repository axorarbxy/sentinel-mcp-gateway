"""Generate reproducible, labeled synthetic multi-tenant event-security traces.

The generated data is a research/demo benchmark, not telemetry from real users
and not a substitute for validation on a target broker deployment.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

MACHINE_LEARNING_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = MACHINE_LEARNING_ROOT / "data" / "event_stream" / "synthetic_event_stream.csv"
DEFAULT_JSONL = MACHINE_LEARNING_ROOT / "data" / "event_stream" / "synthetic_event_stream.jsonl"

NUMERIC_FEATURES = [
    "identity_age_days", "identity_tenant_mismatch", "schema_valid", "schema_drift_score",
    "authorization_allowed", "required_scope_present", "cross_tenant_route",
    "event_age_ms", "inter_arrival_ms", "sequence_gap", "duplicate", "out_of_order",
    "payload_bytes", "payload_depth", "payload_key_count", "payload_hash_reuse_count",
    "graph_fanout_5m", "graph_edge_novel", "consumer_lag", "delivery_attempts",
]
CATEGORICAL_FEATURES = [
    "principal_role", "topic", "event_type", "schema_version", "authorization_decision",
    "broker_partition", "broker_status", "downstream_effect",
]
MODEL_FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES
ATTACK_CLASSES = (
    "schema_drift", "cross_tenant_publish", "authorization_scope_misuse",
    "replay_duplicate", "broker_backpressure", "downstream_privilege_pivot",
)


def _observable_features(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Project a flat training row into the gateway's six observable families."""
    return {
        "identity": {
            "agent_id": row["agent_id"], "tenant_id": row["tenant_id"],
            "principal_role": row["principal_role"], "identity_age_days": row["identity_age_days"],
            "tenant_mismatch": bool(row["identity_tenant_mismatch"]),
        },
        "topics": {
            "broker_topic": row["topic"], "event_type": row["event_type"],
            "schema_version": row["schema_version"], "schema_valid": bool(row["schema_valid"]),
            "schema_drift_score": row["schema_drift_score"],
        },
        "timing": {
            "event_age_ms": row["event_age_ms"], "inter_arrival_ms": row["inter_arrival_ms"],
            "sequence_gap": row["sequence_gap"], "duplicate": bool(row["duplicate"]),
            "out_of_order": bool(row["out_of_order"]),
        },
        "payload_summary": {
            "payload_bytes": row["payload_bytes"], "payload_depth": row["payload_depth"],
            "payload_key_count": row["payload_key_count"],
            "payload_hash_reuse_count": row["payload_hash_reuse_count"],
        },
        "graph_structure": {
            "fanout_5m": row["graph_fanout_5m"], "novel_edge": bool(row["graph_edge_novel"]),
            "downstream_effect": row["downstream_effect"],
        },
        "broker_state": {
            "consumer_lag": row["consumer_lag"], "delivery_attempts": row["delivery_attempts"],
            "partition": row["broker_partition"], "status": row["broker_status"],
        },
    }


def generate_rows(event_count: int = 12_000, seed: int = 42) -> list[dict[str, Any]]:
    """Generate chronological traces with benign context and injected attack sequences."""
    if event_count < 100:
        raise ValueError("event_count must be at least 100 to represent every event class")
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    trace_index = 0
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)

    while len(rows) < event_count:
        trace_index += 1
        trace_id = f"trace-{trace_index:06d}"
        tenant_number = rng.randint(1, 24)
        tenant_id = f"tenant-{tenant_number:02d}"
        agent_id = f"agent-{tenant_number:02d}-{rng.randint(1, 8):02d}"
        # Shorter traces increase the number of independent trace groups, so
        # trace-held-out evaluation has enough examples of every attack class.
        attack_class = rng.choices(("benign", *ATTACK_CLASSES), weights=(60, 7, 7, 7, 7, 6, 6), k=1)[0]
        trace_length = min(rng.randint(8, 16), event_count - len(rows))
        trace_start = start + timedelta(seconds=trace_index * 90)
        base_sequence = rng.randint(1000, 9000)
        last_event_time = trace_start
        trace_rows: list[dict[str, Any]] = []
        topic = f"{tenant_id}.orders"

        for sequence in range(trace_length):
            occurred_at = last_event_time + timedelta(milliseconds=rng.randint(250, 2500))
            last_event_time = occurred_at
            row: dict[str, Any] = {
                "trace_id": trace_id,
                "event_id": f"{trace_id}-event-{sequence:03d}",
                "event_time": occurred_at.isoformat().replace("+00:00", "Z"),
                "sequence": base_sequence + sequence,
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "principal_role": rng.choices(("service", "operator", "viewer"), weights=(78, 17, 5), k=1)[0],
                "identity_age_days": rng.randint(30, 900),
                "identity_tenant_mismatch": 0,
                "topic": topic,
                "event_type": rng.choice(("order.created", "order.updated", "inventory.read")),
                "schema_version": "v1",
                "schema_valid": 1,
                "schema_drift_score": round(rng.uniform(0, 0.12), 4),
                "authorization_decision": "allow",
                "authorization_allowed": 1,
                "required_scope_present": 1,
                "cross_tenant_route": 0,
                "event_age_ms": rng.randint(5, 250),
                "inter_arrival_ms": rng.randint(250, 2500),
                "sequence_gap": 0,
                "duplicate": 0,
                "out_of_order": 0,
                "payload_bytes": rng.randint(180, 1600),
                "payload_depth": rng.randint(2, 5),
                "payload_key_count": rng.randint(4, 18),
                "payload_hash_reuse_count": 1,
                "graph_fanout_5m": rng.randint(1, 3),
                "graph_edge_novel": 0,
                "consumer_lag": rng.randint(0, 150),
                "delivery_attempts": 1,
                "broker_partition": f"p{rng.randint(0, 7)}",
                "broker_status": "healthy",
                "downstream_effect": "normal_order_processing",
                "attack_class": "benign",
            }
            trace_rows.append(row)

        if attack_class != "benign" and trace_rows:
            center = rng.randrange(max(1, trace_length // 3), trace_length)
            row = trace_rows[center]
            row["attack_class"] = attack_class
            if attack_class == "schema_drift":
                row.update(schema_version="v4", schema_valid=0, schema_drift_score=0.94,
                           payload_bytes=rng.randint(9000, 24000), payload_depth=12,
                           downstream_effect="schema_reject_then_retry")
            elif attack_class == "cross_tenant_publish":
                other_tenant = f"tenant-{(tenant_number % 24) + 1:02d}"
                row.update(topic=f"{other_tenant}.orders", identity_tenant_mismatch=1,
                           cross_tenant_route=1, graph_edge_novel=1,
                           downstream_effect="cross_tenant_data_visible")
            elif attack_class == "authorization_scope_misuse":
                row.update(principal_role="viewer", authorization_decision="allow_scope_mismatch",
                           authorization_allowed=1, required_scope_present=0,
                           downstream_effect="unauthorized_admin_action")
            elif attack_class == "replay_duplicate":
                row.update(event_age_ms=rng.randint(120_000, 900_000), inter_arrival_ms=rng.randint(1, 8),
                           sequence_gap=-rng.randint(1, 25), duplicate=1, out_of_order=1,
                           payload_hash_reuse_count=rng.randint(8, 40), delivery_attempts=rng.randint(3, 8),
                           downstream_effect="duplicate_payment_or_action")
            elif attack_class == "broker_backpressure":
                row.update(event_age_ms=rng.randint(60_000, 600_000), inter_arrival_ms=rng.randint(1, 10),
                           consumer_lag=rng.randint(8000, 50000), delivery_attempts=rng.randint(5, 15),
                           broker_status="backlogged", downstream_effect="delayed_or_reordered_effect")
            elif attack_class == "downstream_privilege_pivot":
                row.update(principal_role="service", graph_fanout_5m=rng.randint(12, 40),
                           graph_edge_novel=1, downstream_effect="privileged_export_or_deploy")

        for row in trace_rows:
            row["observable_features"] = _observable_features(row)
            rows.append(row)

    return rows[:event_count]


def write_dataset(rows: list[dict[str, Any]], csv_path: Path, jsonl_path: Path | None = None) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "trace_id", "event_id", "event_time", "sequence", "agent_id", "tenant_id",
        "principal_role", "identity_age_days", "identity_tenant_mismatch", "topic", "event_type",
        "schema_version", "schema_valid", "schema_drift_score", "authorization_decision",
        "authorization_allowed", "required_scope_present", "cross_tenant_route", "event_age_ms",
        "inter_arrival_ms", "sequence_gap", "duplicate", "out_of_order", "payload_bytes",
        "payload_depth", "payload_key_count", "payload_hash_reuse_count", "graph_fanout_5m",
        "graph_edge_novel", "consumer_lag", "delivery_attempts", "broker_partition", "broker_status",
        "downstream_effect", "attack_class",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows({key: row[key] for key in fieldnames} for row in rows)

    if jsonl_path is not None:
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with jsonl_path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")

    card = {
        "title": "Sentinel synthetic multi-tenant event-stream security dataset",
        "synthetic": True,
        "seed": "caller-specified; default 42",
        "events": len(rows),
        "traces": len({row["trace_id"] for row in rows}),
        "classes": {label: sum(row["attack_class"] == label for row in rows)
                    for label in ("benign", *ATTACK_CLASSES)},
        "families": ["identity", "topics_and_schema", "timing_and_ordering", "payload_summary",
                     "graph_and_downstream_effects", "broker_state", "authorization"],
        "limitations": [
            "Generated from authored scenario distributions; not a measurement of real production prevalence.",
            "Use trace-grouped splits and calibrate on the target broker and policy configuration.",
            "No raw payload content, credentials, or personal data are generated.",
        ],
    }
    card_path = csv_path.with_name("dataset_card.json")
    card_path.write_text(json.dumps(card, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=12_000, help="number of synthetic events to generate")
    parser.add_argument("--seed", type=int, default=42, help="reproducible random seed")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="output CSV path")
    parser.add_argument("--jsonl", type=Path, default=DEFAULT_JSONL, help="output nested-feature JSONL path")
    args = parser.parse_args()
    rows = generate_rows(args.events, args.seed)
    write_dataset(rows, args.output, args.jsonl)
    print(f"Generated {len(rows):,} labeled synthetic events across {len({r['trace_id'] for r in rows}):,} traces")
    print(f"CSV: {args.output}")
    print(f"JSONL: {args.jsonl}")
    print(f"Dataset card: {args.output.with_name('dataset_card.json')}")


if __name__ == "__main__":
    main()
