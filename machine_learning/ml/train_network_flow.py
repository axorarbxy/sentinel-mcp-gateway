from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from ml.config import ARTIFACTS_DIR, PROJECT_ROOT


TRAIN_PATH = PROJECT_ROOT / "data" / "UNSW_NB15_training-set(in).csv"
TEST_PATH = PROJECT_ROOT / "data" / "UNSW_NB15_testing-set(in).csv"
MODEL_PATH = ARTIFACTS_DIR / "network_flow_rf.joblib"
METRICS_PATH = ARTIFACTS_DIR / "network_flow_metrics.json"
MODEL_CARD_PATH = ARTIFACTS_DIR / "network_flow_model_card.md"
TARGET = "label"
LEAKAGE_COLUMNS = {"id", "attack_cat", TARGET}


def _load_split(path: Path) -> tuple[pd.DataFrame, pd.Series]:
    frame = pd.read_csv(path, encoding_errors="replace")
    if TARGET not in frame.columns:
        raise ValueError(f"{path.name} is missing required target column {TARGET!r}")
    if frame[TARGET].isna().any() or not set(frame[TARGET].unique()).issubset({0, 1}):
        raise ValueError(f"{path.name} target {TARGET!r} must contain only non-null 0/1 values")

    labels = frame[TARGET].astype("int8")
    features = frame.drop(columns=[column for column in LEAKAGE_COLUMNS if column in frame.columns])
    return features, labels


def train_network_flow_model() -> tuple[Pipeline, dict]:
    X_train, y_train = _load_split(TRAIN_PATH)
    X_test, y_test = _load_split(TEST_PATH)
    if set(X_train.columns) != set(X_test.columns):
        raise ValueError("Training and test CSV feature columns do not match")
    X_test = X_test.reindex(columns=X_train.columns)

    categorical_columns = X_train.select_dtypes(include=["object", "category", "string"]).columns.tolist()
    numeric_columns = [column for column in X_train.columns if column not in categorical_columns]
    preprocessing = ColumnTransformer(
        transformers=[
            ("numeric", SimpleImputer(strategy="median"), numeric_columns),
            (
                "categorical",
                Pipeline([
                    ("imputer", SimpleImputer(strategy="most_frequent")),
                    ("one_hot", OneHotEncoder(handle_unknown="ignore")),
                ]),
                categorical_columns,
            ),
        ],
        remainder="drop",
    )
    model = Pipeline([
        ("features", preprocessing),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=160,
                max_depth=24,
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                n_jobs=-1,
                random_state=42,
            ),
        ),
    ])
    model.fit(X_train, y_train)

    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= 0.5).astype("int8")
    tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=[0, 1]).ravel()
    metrics = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "pr_auc": float(average_precision_score(y_test, probabilities)),
        "threshold": 0.5,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "test_rows": int(len(y_test)),
        "train_rows": int(len(y_train)),
        "feature_columns": X_train.columns.tolist(),
        "excluded_columns": sorted(LEAKAGE_COLUMNS),
        "train_class_counts": {str(key): int(value) for key, value in y_train.value_counts().sort_index().items()},
        "test_class_counts": {str(key): int(value) for key, value in y_test.value_counts().sort_index().items()},
    }

    trained_at = datetime.now(timezone.utc).isoformat()
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps({"model": "UNSW-NB15 binary network-flow Random Forest", "trained_at": trained_at, **metrics}, indent=2), encoding="utf-8")
    MODEL_CARD_PATH.write_text(
        "# UNSW-NB15 Network-Flow Random Forest\n\n"
        f"- Trained at: {trained_at}\n"
        "- Task: binary classification of benign (0) versus attack (1) network flows.\n"
        f"- Data: `{TRAIN_PATH.relative_to(PROJECT_ROOT)}` for training and `{TEST_PATH.relative_to(PROJECT_ROOT)}` for held-out evaluation.\n"
        "- Preprocessing: median imputation for numeric features; most-frequent imputation and one-hot encoding for categorical features.\n"
        "- Excluded from features: `id` and `attack_cat` to prevent identifier and attack-category target leakage; `label` is the target.\n"
        "- This is a separate network-flow model; it does not replace or feed the text-payload classifier.\n"
        "- Metrics below are measured on the supplied test split at a 0.5 probability threshold.\n\n"
        "```json\n"
        + json.dumps({key: value for key, value in metrics.items() if key not in {"feature_columns", "excluded_columns", "train_class_counts", "test_class_counts"}}, indent=2)
        + "\n```\n",
        encoding="utf-8",
    )
    return model, metrics


if __name__ == "__main__":
    _, results = train_network_flow_model()
    print(json.dumps({key: value for key, value in results.items() if key != "feature_columns"}, indent=2))