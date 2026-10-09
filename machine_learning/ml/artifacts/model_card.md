# Payload Random Forest Model Card

- Model: Random forest payload classifier
- Version: payload-rf-v1
- Training date: 2026-10-06T19:07:54.280630+00:00
- Rule engine: main defense layer remains authoritative; this model only adds risk scoring.
- Data source: synthetic payload corpus generated from shell, SQLi, path traversal, script tags, and benign command/path examples because the repo's `machine_learning/data/` directory contains network feature CSVs, not labeled text payload corpus.
- Thresholds: warn >= 0.5, block >= 0.85
- Metrics: accuracy=0.7500, precision=0.6667, recall=1.0000, F1=0.8000, ROC-AUC=0.7500, PR-AUC=0.8333
- Limitations: performance on real MCP traffic is not guaranteed because the training data is synthetic and public-domain pattern inspired rather than directly collected from an MCP environment.
