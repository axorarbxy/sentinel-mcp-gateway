# ML data inventory and payload-classifier notes

## Data files in `machine_learning/data/`

The `machine_learning/data/` directory contains only numeric intrusion-detection CSVs and no labeled text-payload corpus. The payload classifier therefore uses a synthetic, clearly labeled text corpus generated from shell, SQL, path traversal, script injection, and benign command/path examples.

| File | Size | Rows | Columns | Type | Use |
| --- | ---: | ---: | --- | --- | --- |
| `machine_learning/data/NUSW-NB15_features(in).csv` | inspect locally | inspect locally | inspect locally | numeric network features | optional behavioral model only, not used for payload classifier |
| `machine_learning/data/NUSW-NB15_GT(in).csv` | inspect locally | inspect locally | inspect locally | numeric labels / traffic metadata | ground truth for network datasets |
| `machine_learning/data/UNSW-NB15_4(in).csv` | inspect locally | inspect locally | inspect locally | numeric network features | optional behavioral model only |
| `machine_learning/data/UNSW-NB15_LIST_EVENTS(in).csv` | inspect locally | inspect locally | inspect locally | event metadata | optional behavioral model only |
| `machine_learning/data/UNSW_NB15_testing-set(in).csv` | 15,380,797 | 82,332 | 45 | numeric/categorical network features + `attack_cat` and binary `label` | held-out evaluation for network-flow model |
| `machine_learning/data/UNSW_NB15_training-set(in).csv` | 32,293,015 | 175,341 | 45 | numeric/categorical network features + `attack_cat` and binary `label` | training for network-flow model |

### Data file classification

- `NUSW-NB15_*`, `UNSW-NB15_*`: numeric network/behavior features; not text payloads.
- No file in `machine_learning/data/` contains raw SQL queries, HTTP requests, shell commands, or paths with a label column suitable for the payload model.
- The UNSW train/test pair does contain labeled network flows: `label` is binary (0 benign, 1 attack), and `attack_cat` contains attack-family labels.

## Label distribution and class imbalance

Because the repo has no text payload datasets, the payload model uses a synthetic corpus with a class balance chosen to keep the malicious class visible while avoiding degenerate training:

- benign examples: ~45%
- malicious examples: ~55%

This is intentionally modestly imbalanced to reflect the fact that real-world payloads contain more benign traffic than malicious examples, but the malicious class still remains strongly represented.

## Synthetic payload generation used for the classifier

The payload corpus is generated from a mix of:

- benign shell commands: `ls -la`, `cat README.md`, `grep -R import src`
- benign SQL reads: `SELECT name FROM users WHERE id = 1`
- malicious SQLi payloads: `OR 1=1`, `UNION SELECT`, `DROP TABLE`, comment-based bypasses
- path traversal attempts: `../../etc/passwd`, `..\\..\\Windows\\System32\\drivers\\etc\\hosts`
- command injection: `curl ... | bash`, `wget ... && chmod +x`
- script injection: `<script>alert('x')</script>`

This synthetic set is deliberately small but varied enough to teach the model that a normal command or path is not inherently malicious while still catching the high-signal attack forms that the gateway already blocks with hard rules.

## Problems and caveats

- No repo-local text payload dataset is present, so there is no direct evidence that the model generalizes to a real MCP environment.
- Synthetic examples may not mirror the exact distribution of production MCP calls.
- Numeric network datasets are separate from the payload model and should not be mixed in without a separate behavioral model.
- Unlike real-world datasets, these synthetic examples are intentionally compact and reproducible for local evaluation.

## Use in the project

- `machine_learning/ml/prepare_data.py`: builds the payload training set, normalizes text, strips duplicates, and splits into train/validation/test.
- `machine_learning/ml/train.py`: trains the Random Forest payload model and saves `machine_learning/ml/artifacts/payload_rf.joblib`.
- `machine_learning/ml/inference.py`: scores incoming payload text at runtime, falls back safely if the model is missing, and keeps the rule engine authoritative.
- `machine_learning/ml/train_network_flow.py`: trains a separate binary network-flow Random Forest from the UNSW train/test pair. It excludes `id` and `attack_cat` from features, evaluates on the provided test split, and writes `network_flow_rf.joblib`, `network_flow_metrics.json`, and `network_flow_model_card.md` under `machine_learning/ml/artifacts/`.

## Website feature mapping

- **Phishing Detection:** `machine_learning/ml_models/phishing_detector/models/phishing_xgb.pkl` and `phishing_rf.pkl` score submitted URLs through `/ml/analyze/url`.
- **QR Scanner:** uploaded QR images are scored by the CNN (`machine_learning/models/best_cnn_model.pth`) and five-feature XGBoost (`machine_learning/models/xgb_model.pkl` with `machine_learning/models/scaler.pkl`); decoded URL content is scored separately with the QR URL XGBoost and Random Forest models in `machine_learning/ml_models/qr_scanner/models/`. The serialized QR ensemble is shown as a separate experimental advisory score and does not alter the primary verdict.
- **Network IDS:** `machine_learning/ml/artifacts/network_flow_rf.joblib` scores UNSW-NB15-compatible CSV rows through the Flow Classifier tab. Uploads are limited to 2 MB and 250 rows and are not persisted.
- **Payload Analyzer and MCP protection:** `machine_learning/ml/artifacts/payload_rf.joblib` scores user-submitted text in the Payload Analyzer and MCP tool-call arguments in the gateway interception path; hard policy checks remain authoritative.
- The broken root-level serialized QR ensemble pickle was removed because it referenced a training-only `__main__.QRCNN` class. The nested serialized ensemble is loaded with its legacy package path and matching ten-feature preprocessor; because its training provenance differs from the primary real-data image models, it is surfaced as experimental and excluded from the primary verdict. PyTorch loading is optional at runtime, and QR URL analysis remains available if the image models cannot load.
