from __future__ import annotations

import json
import os
import re
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


def _rule_signals(text: str) -> tuple[float, list[str]]:
    """Detect a small set of high-confidence attack shapes independently of ML."""
    value = text.lower()
    signals: list[str] = []
    severity = 0.0

    sql_injection = (
        r"\bunion\s+(?:all\s+)?select\b",
        r"\bor\s+['\"]?\s*1\s*['\"]?\s*=\s*['\"]?\s*1\b",
        r";\s*(?:drop|truncate|alter|delete|update|insert)\b",
        r"\b(?:sleep|benchmark)\s*\(",
    )
    if any(re.search(pattern, value) for pattern in sql_injection):
        signals.append("SQL injection pattern")
        severity = max(severity, 0.98)

    if re.search(r"(?:\.\.[/\\]){2,}|%2e%2e(?:%2f|%5c){2,}|/etc/(?:passwd|shadow)", value):
        signals.append("path traversal pattern")
        severity = max(severity, 0.93)

    shell_command = r"(?:curl|wget)\s+\S+\s*\|\s*(?:sh|bash)\b|\b(?:rm\s+-rf|chmod\s+[0-7]{3,4}|nc\s+-[elp])\b"
    if re.search(shell_command, value):
        signals.append("dangerous shell command pattern")
        severity = max(severity, 0.98)
    elif re.search(r"(?:;|&&|\|\|)\s*(?:bash|sh|powershell|cmd(?:\.exe)?)\b", value):
        signals.append("chained shell execution pattern")
        severity = max(severity, 0.82)

    return severity, signals


def score_payload(text: Any) -> dict:
    model = _ensure_model_loaded()
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

    model_score = 0.0
    inference_failed = False
    if model is not None:
        try:
            probabilities = model.predict_proba(values)[:, 1]
            model_score = float(max(probabilities))
        except Exception:
            inference_failed = True

    rule_score, rule_signals = _rule_signals(" ".join(values))
    # This artifact has weak validation results and tends to assign borderline
    # risk to ordinary prose. Treat probabilities below 65% as inconclusive;
    # explicit rule matches remain decisive, and stronger model signals still
    # contribute for patterns the rules do not cover.
    model_signal_threshold = max(WARN_THRESHOLD, 0.65)
    model_contribution = model_score if model_score >= model_signal_threshold else 0.0
    score = max(model_contribution, rule_score)

    if score >= BLOCK_THRESHOLD:
        decision = "BLOCK"
        label = 1
    elif score >= WARN_THRESHOLD:
        decision = "WARN"
        label = 1
    else:
        decision = "ALLOW"
        label = 0

    top_signals = list(rule_signals)
    if model_contribution >= WARN_THRESHOLD and not top_signals:
        top_signals.append("model detected unusual payload characteristics")
    if not top_signals:
        top_signals.append("no known high-confidence attack pattern")

    return {
        "score": round(score, 4),
        "label": int(label),
        "top_signals": top_signals or ["normal request"],
        "decision": decision,
        "fallback": model is None or inference_failed,
        "model_score": round(model_score, 4),
        "rule_score": round(rule_score, 4),
        "model_available": model is not None and not inference_failed,
        "model_version": MODEL_VERSION,
    }
