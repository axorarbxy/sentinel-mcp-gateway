from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV

from ml.config import ARTIFACTS_DIR, BLOCK_THRESHOLD, METRICS_PATH, MODEL_CARD_PATH, MODEL_PATH, WARN_THRESHOLD
from ml.evaluate import save_metric_assets
from ml.features import PayloadFeatureTransformer
from ml.prepare_data import build_payload_dataset


def _search_space():
    return {
        "model__n_estimators": [100, 200, 300],
        "model__max_depth": [None, 8, 16, 24],
        "model__min_samples_leaf": [1, 2, 4],
        "model__max_features": ["sqrt", "log2", None],
    }


def train_payload_model():
    from sklearn.pipeline import Pipeline

    train_df, valid_df, test_df = build_payload_dataset()
    X_train = train_df["payload"]
    y_train = train_df["label"]
    X_test = test_df["payload"]
    y_test = test_df["label"]

    pipeline = Pipeline([
        ("features", PayloadFeatureTransformer(max_features=20000, ngram_range=(2, 5), analyzer="char")),
        ("model", RandomForestClassifier(class_weight="balanced", n_jobs=-1, random_state=42, n_estimators=200)),
    ])

    search = RandomizedSearchCV(
        estimator=pipeline,
        param_distributions=_search_space(),
        n_iter=8,
        cv=3,
        scoring="recall",
        n_jobs=-1,
        random_state=42,
        refit=True,
    )
    search.fit(X_train, y_train)
    model = search.best_estimator_
    metrics = save_metric_assets(model, X_test, y_test)

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    training_date = datetime.now(timezone.utc).isoformat()
    model_card = f"""# Payload Random Forest Model Card

- Model: Random forest payload classifier
- Version: payload-rf-v1
- Training date: {training_date}
- Rule engine: main defense layer remains authoritative; this model only adds risk scoring.
- Data source: synthetic payload corpus generated from shell, SQLi, path traversal, script tags, and benign command/path examples because the repo's `machine_learning/data/` directory contains network feature CSVs, not labeled text payload corpus.
- Thresholds: warn >= {WARN_THRESHOLD}, block >= {BLOCK_THRESHOLD}
- Metrics: accuracy={metrics['accuracy']:.4f}, precision={metrics['precision']:.4f}, recall={metrics['recall']:.4f}, F1={metrics['f1']:.4f}, ROC-AUC={metrics['roc_auc']:.4f}, PR-AUC={metrics['pr_auc']:.4f}
- Limitations: performance on real MCP traffic is not guaranteed because the training data is synthetic and public-domain pattern inspired rather than directly collected from an MCP environment.
"""
    MODEL_CARD_PATH.write_text(model_card, encoding="utf-8")

    payload = {
        "model_version": "payload-rf-v1",
        "trained_at": training_date,
        "thresholds": {"warn": WARN_THRESHOLD, "block": BLOCK_THRESHOLD},
        "metrics": metrics,
    }
    with METRICS_PATH.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    return model, metrics


if __name__ == "__main__":
    train_payload_model()
