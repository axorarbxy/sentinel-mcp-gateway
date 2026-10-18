# Multi-tenant event-stream security benchmark

This folder is the workspace for a reproducible synthetic event dataset and any
external traces you choose to add. The generator emits CSV for training and
nested JSONL that preserves the event envelope and six observable feature
families. It creates synthetic tenants, principals, topics, schema versions,
authorization outcomes, timing/replay signals, broker pressure, graph fan-out,
and downstream effects. Every row carries an `attack_class` label.

## Generate and train

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe machine_learning\ml\event_stream_dataset.py --events 12000 --seed 42
.\.venv\Scripts\python.exe machine_learning\ml\train_event_stream_model.py
```

The trainer splits by `trace_id`, so events from one trace cannot appear in both
training and validation. The model and metrics are written to
`machine_learning/ml/artifacts/event_stream_synthetic_model.joblib` and
`event_stream_synthetic_model.metrics.json`.

## Bring an external dataset

Place raw downloads under `machine_learning/data/event_stream/external/` and
keep their license and source documentation alongside them. External datasets
will need a documented adapter into the feature columns before they can be
combined with this benchmark. Do not map packet labels directly onto broker
authorization or downstream-effect labels without evidence.

The generated data is for prototyping only. Its attack patterns and class
balance are authored, not measured from a production deployment. The trained
artifact is an offline benchmark and is not loaded by the live gateway.
