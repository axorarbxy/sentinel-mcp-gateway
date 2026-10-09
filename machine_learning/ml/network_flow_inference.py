from __future__ import annotations

import json
from functools import lru_cache
from io import BytesIO

import joblib
import pandas as pd

from ml.config import ARTIFACTS_DIR


MODEL_PATH = ARTIFACTS_DIR / "network_flow_rf.joblib"
METRICS_PATH = ARTIFACTS_DIR / "network_flow_metrics.json"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_ROWS = 250


@lru_cache(maxsize=1)
def _load_model():
    if not MODEL_PATH.is_file():
        raise FileNotFoundError("Network-flow model artifact is not available")
    return joblib.load(MODEL_PATH)


def get_network_flow_model_info() -> dict:
    try:
        model = _load_model()
    except Exception as exc:
        return {"loaded": False, "error": str(exc), "metrics": {}}

    metrics = {}
    if METRICS_PATH.is_file():
        try:
            metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            metrics = {}
    return {
        "loaded": model is not None,
        "model": "UNSW-NB15 binary network-flow Random Forest",
        "threshold": 0.5,
        "metrics": metrics,
    }


def score_network_flow_csv(content: bytes) -> dict:
    if not content:
        raise ValueError("Upload a non-empty CSV file")
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError(f"CSV must be no larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")

    try:
        frame = pd.read_csv(BytesIO(content), encoding_errors="replace", nrows=MAX_ROWS + 1)
    except (pd.errors.ParserError, UnicodeError, ValueError) as exc:
        raise ValueError(f"Could not read CSV: {exc}") from exc
    if frame.empty:
        raise ValueError("CSV must contain at least one data row")
    if len(frame) > MAX_ROWS:
        raise ValueError(f"CSV is limited to {MAX_ROWS} rows per analysis")

    model = _load_model()
    feature_columns = list(getattr(model, "feature_names_in_", []))
    if not feature_columns:
        feature_columns = list(model.named_steps["features"].feature_names_in_)
    missing = [column for column in feature_columns if column not in frame.columns]
    if missing:
        preview = ", ".join(missing[:8])
        suffix = "..." if len(missing) > 8 else ""
        raise ValueError(f"CSV is missing required UNSW-NB15 feature columns: {preview}{suffix}")

    features = frame.loc[:, feature_columns].copy()
    numeric_columns = model.named_steps["features"].transformers_[0][2]
    for column in numeric_columns:
        features[column] = pd.to_numeric(features[column], errors="coerce")

    probabilities = model.predict_proba(features)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    return {
        "model": "UNSW-NB15 binary network-flow Random Forest",
        "threshold": 0.5,
        "rows_scored": int(len(frame)),
        "attacks_flagged": int(predictions.sum()),
        "results": [
            {
                "row": index + 1,
                "prediction": "attack" if int(prediction) else "benign",
                "attack_probability": round(float(probability), 4),
            }
            for index, (prediction, probability) in enumerate(zip(predictions, probabilities))
        ],
    }