from __future__ import annotations

import math
import re
from typing import Iterable, Sequence

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer

SQL_KEYWORDS = ["select", "union", "or 1=1", "--", ";", "drop", "delete", "insert", "update", "sleep("]
SHELL_MARKERS = [";", "|", "&", "&&", "||", "$(", "`", "$(", "cat ", "curl ", "wget ", "chmod ", "bash "]
PATH_TRAVERSAL_PATTERNS = [r"\.\./", r"\.\.\\", r"%2e%2e", r"\x00"]


class PayloadFeatureTransformer(BaseEstimator, TransformerMixin):
    """Combine character n-gram TF-IDF with a small set of handcrafted signals."""

    def __init__(self, max_features: int = 20000, ngram_range=(2, 5), analyzer: str = "char"):
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.analyzer = analyzer
        self.vectorizer = None

    def fit(self, X, y=None):
        texts = _coerce_texts(X)
        self.vectorizer = TfidfVectorizer(
            analyzer=self.analyzer,
            ngram_range=self.ngram_range,
            max_features=self.max_features,
        )
        self.vectorizer.fit(texts)
        return self

    def transform(self, X):
        texts = _coerce_texts(X)
        tfidf = self.vectorizer.transform(texts)
        hand = np.asarray([_handcrafted_features(text) for text in texts], dtype=np.float32)
        if sparse.issparse(tfidf):
            return sparse.hstack([tfidf, sparse.csr_matrix(hand)], format="csr")
        return np.hstack([tfidf.toarray(), hand])

    def get_feature_names_out(self):
        if self.vectorizer is None:
            return []
        names = [f"tfidf_{name}" for name in self.vectorizer.get_feature_names_out()]
        for name in _HANDCRAFTED_NAMES:
            names.append(f"manual_{name}")
        return np.asarray(names, dtype=object)


def _coerce_texts(values: Iterable[str] | Sequence[str] | str) -> list[str]:
    if isinstance(values, str):
        return [values]
    if hasattr(values, "tolist"):
        values = values.tolist()
    if not isinstance(values, (list, tuple)):
        values = list(values)
    result: list[str] = []
    for item in values:
        if item is None:
            result.append("")
        else:
            result.append(str(item))
    return result


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {char: text.count(char) for char in set(text)}
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _count_url_encoded(text: str) -> int:
    return len(re.findall(r"%[0-9A-Fa-f]{2}", text))


def _handcrafted_features(text: str) -> np.ndarray:
    text = text or ""
    lower = text.lower()
    special_chars = sum(1 for ch in text if not ch.isalnum() and not ch.isspace())
    digits = sum(1 for ch in text if ch.isdigit())
    length = float(len(text))
    sql_hits = sum(1 for word in SQL_KEYWORDS if word in lower)
    shell_hits = sum(1 for marker in SHELL_MARKERS if marker in lower)
    traversal_hits = sum(1 for pattern in PATH_TRAVERSAL_PATTERNS if re.search(pattern, lower))
    script_tags = int("<script" in lower or "javascript:" in lower)
    url_encoded = _count_url_encoded(text)
    entropy = _shannon_entropy(text)
    return np.array(
        [
            length,
            special_chars,
            digits / max(len(text), 1),
            entropy,
            traversal_hits,
            sql_hits,
            shell_hits,
            url_encoded,
            script_tags,
            int("../" in lower or "..\\" in lower),
            int("||" in lower or "&&" in lower),
        ],
        dtype=np.float32,
    )


_HANDCRAFTED_NAMES = [
    "length",
    "special_chars",
    "digit_ratio",
    "entropy",
    "traversal_hits",
    "sql_hits",
    "shell_hits",
    "url_encoded_count",
    "script_tag_present",
    "dotdot_present",
    "shell_chain_present",
]
