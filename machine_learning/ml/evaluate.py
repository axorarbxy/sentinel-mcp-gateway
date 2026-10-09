from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

from ml.config import ARTIFACTS_DIR, METRICS_PATH


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def evaluate_model(model, X_test, y_test):
    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
        "pr_auc": float(average_precision_score(y_test, y_prob)),
        "fpr": float(fp / max(fp + tn, 1)),
        "fnr": float(fn / max(fn + tp, 1)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "macro_precision": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
    }

    feature_names = getattr(model.named_steps["features"], "get_feature_names_out", lambda: [])()
    importances = getattr(model.named_steps["model"], "feature_importances_", np.zeros(len(feature_names)))
    if len(feature_names) == 0:
        feature_names = [f"feature_{idx}" for idx in range(len(importances))]
    ranked = sorted(zip(feature_names, importances), key=lambda item: float(item[1]), reverse=True)[:20]
    metrics["top_features"] = [{"feature": name, "importance": _safe_float(importance)} for name, importance in ranked]
    return metrics


def save_metric_assets(model, X_test, y_test):
    metrics = evaluate_model(model, X_test, y_test)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    with METRICS_PATH.open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)

    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    fig, ax = plt.subplots(figsize=(5, 5))
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    ax.imshow(cm, interpolation="nearest", cmap="Blues")
    ax.set_title("Confusion matrix")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["benign", "malicious"])
    ax.set_yticklabels(["benign", "malicious"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center", color="black")
    fig.tight_layout()
    fig.savefig(ARTIFACTS_DIR / "confusion_matrix.png", dpi=150)
    plt.close(fig)

    precision, recall, _ = precision_recall_curve(y_test, y_prob)
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(recall, precision)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall curve")
    fig.tight_layout()
    fig.savefig(ARTIFACTS_DIR / "precision_recall_curve.png", dpi=150)
    plt.close(fig)

    feature_names = getattr(model.named_steps["features"], "get_feature_names_out", lambda: [])()
    importances = model.named_steps["model"].feature_importances_
    if len(feature_names) == 0:
        feature_names = [f"feature_{idx}" for idx in range(len(importances))]
    top = sorted(zip(feature_names, importances), key=lambda item: item[1], reverse=True)[:10]
    fig, ax = plt.subplots(figsize=(8, 5))
    labels = [item[0] for item in top]
    values = [item[1] for item in top]
    ax.barh(labels[::-1], values[::-1], color="#4c78a8")
    ax.set_title("Top feature importances")
    fig.tight_layout()
    fig.savefig(ARTIFACTS_DIR / "feature_importance.png", dpi=150)
    plt.close(fig)

    return metrics
