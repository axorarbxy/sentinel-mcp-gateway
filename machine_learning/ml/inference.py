from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import joblib

from ml.config import BLOCK_THRESHOLD, MODEL_PATH, MODEL_VERSION, WARN_THRESHOLD

_LOAD_ERROR = None
_MODEL = None


def _flatten_strings(value: Any, out: list[str] | None = None):
    out = out if out is not None else []
    if isinstance(value, dict):
        for item in value.values():
            _flatten_strings(item, out)
    elif isinstance(value, list):
        for item in value:
            _flatten_strings(item, out)
    elif isinstance(value, tuple):
        for item in value:
            _flatten_strings(item, out)
    elif isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            out.append(cleaned)
    return out


def _model_path() -> Path:
    return MODEL_PATH


def _ensure_model_loaded():
    global _MODEL
    if _MODEL is not None:
        return _MODEL
    try:
        model_path = _model_path()
        if not model_path.exists():
            try:
                from ml.train import train_payload_model

                train_payload_model()
            except Exception:
                return None
            if not model_path.exists():
                return None
        _MODEL = joblib.load(model_path)
        return _MODEL
    except Exception as exc:  # pragma: no cover - runtime fallback
        global _LOAD_ERROR
        _LOAD_ERROR = exc
        return None


def get_model_info():
    model = _ensure_model_loaded()
    metrics_path = Path(__file__).resolve().parent / "artifacts" / "metrics.json"
    metrics = {}
    if metrics_path.exists():
        try:
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            metrics = {}
    return {
        "model_loaded": model is not None,
        "model_version": MODEL_VERSION,
        "metrics": metrics.get("metrics", metrics),
        "thresholds": {"warn": WARN_THRESHOLD, "block": BLOCK_THRESHOLD},
        "fallback": model is None,
    }


def score_payload(text: Any) -> dict:
    model = _ensure_model_loaded()
    if model is None:
        return {
            "score": 0.0,
            "label": 0,
            "top_signals": ["model unavailable"],
            "decision": "ALLOW",
            "fallback": True,
            "model_version": MODEL_VERSION,
        }

    values = _flatten_strings(text)
    if not values:
        return {
            "score": 0.0,
            "label": 0,
            "top_signals": ["no payload text"],
            "decision": "ALLOW",
            "fallback": False,
            "model_version": MODEL_VERSION,
        }

    try:
        probabilities = model.predict_proba(values)[:, 1]
        score = float(max(probabilities))
    except Exception:
        return {
            "score": 0.0,
            "label": 0,
            "top_signals": ["inference failed"],
            "decision": "ALLOW",
            "fallback": True,
            "model_version": MODEL_VERSION,
        }

    if score >= BLOCK_THRESHOLD:
        decision = "BLOCK"
        label = 1
    elif score >= WARN_THRESHOLD:
        decision = "WARN"
        label = 1
    else:
        decision = "ALLOW"
        label = 0

    top_signals = []
    if score >= WARN_THRESHOLD:
        lower = " ".join(values).lower()
        if any(token in lower for token in ["union", "select", "or 1=1", "--", "drop", "delete"]):
            top_signals.append("sql pattern")
        if any(token in lower for token in ["../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow"]):
            top_signals.append("path traversal")
        if any(token in lower for token in ["curl ", "wget ", "| bash", "&&", ";", "chmod ", "nc "]):
            top_signals.append("command execution")
        if not top_signals:
            top_signals.append("suspicious payload")

    return {
        "score": round(score, 4),
        "label": int(label),
        "top_signals": top_signals or ["normal request"],
        "decision": decision,
        "fallback": False,
        "model_version": MODEL_VERSION,
    }
