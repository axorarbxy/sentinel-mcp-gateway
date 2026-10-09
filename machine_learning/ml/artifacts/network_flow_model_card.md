# UNSW-NB15 Network-Flow Random Forest

- Trained at: 2026-10-06T19:20:30.790012+00:00
- Task: binary classification of benign (0) versus attack (1) network flows.
- Data: `machine_learning\data\UNSW_NB15_training-set(in).csv` for training and `machine_learning\data\UNSW_NB15_testing-set(in).csv` for held-out evaluation.
- Preprocessing: median imputation for numeric features; most-frequent imputation and one-hot encoding for categorical features.
- Excluded from features: `id` and `attack_cat` to prevent identifier and attack-category target leakage; `label` is the target.
- This is a separate network-flow model; it does not replace or feed the text-payload classifier.
- Metrics below are measured on the supplied test split at a 0.5 probability threshold.

```json
{
  "accuracy": 0.8996987805470534,
  "precision": 0.8602635363625762,
  "recall": 0.9764404835436337,
  "f1": 0.9146777426487301,
  "roc_auc": 0.9845235496791241,
  "pr_auc": 0.9883718975487711,
  "threshold": 0.5,
  "confusion_matrix": {
    "tn": 29810,
    "fp": 7190,
    "fn": 1068,
    "tp": 44264
  },
  "test_rows": 82332,
  "train_rows": 175341
}
```
