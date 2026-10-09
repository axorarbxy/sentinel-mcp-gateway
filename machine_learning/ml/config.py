from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ML_ROOT = Path(__file__).resolve().parent
ARTIFACTS_DIR = ML_ROOT / "artifacts"
MODEL_PATH = ARTIFACTS_DIR / "payload_rf.joblib"
METRICS_PATH = ARTIFACTS_DIR / "metrics.json"
MODEL_CARD_PATH = ARTIFACTS_DIR / "model_card.md"

WARN_THRESHOLD = float(os.getenv("CYBEREYE_WARN_THRESHOLD", "0.50"))
BLOCK_THRESHOLD = float(os.getenv("CYBEREYE_BLOCK_THRESHOLD", "0.85"))
MODEL_VERSION = os.getenv("CYBEREYE_MODEL_VERSION", "payload-rf-v1")
TRAINED_AT = os.getenv("CYBEREYE_MODEL_TRAINED_AT", "unknown")
