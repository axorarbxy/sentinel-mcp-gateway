"""Offline tests for the URL-analysis API and feature extraction."""

import numpy as np
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import ml_scanner


@pytest.mark.parametrize("url", [
    "https://example.com/login",
    "http://paypa1-secure.example.invalid/verify?next=%2Faccount",
    "https://xn--pple-43d.com/",
])
def test_url_feature_extraction_is_fixed_width_and_finite(url):
    features = ml_scanner.extract_url_features(url)
    assert features.shape == (26,)
    assert np.isfinite(features).all()


def test_unavailable_models_fail_closed_to_neutral_advisory(monkeypatch):
    monkeypatch.setattr(ml_scanner, "MODELS_LOADED", False)
    monkeypatch.setattr(ml_scanner, "PHISHING_MODELS_LOADED", False)
    result = ml_scanner.analyze_url("https://example.invalid", model_type="phishing")
    assert result["is_malicious"] is False
    assert result["confidence"] == 0.5
    assert result["risk_factors"] == ["Model not loaded"]


def test_url_api_returns_typed_result_without_network(monkeypatch):
    expected = {
        "is_malicious": True,
        "confidence": 0.91,
        "risk_factors": ["Typosquatting: paypa1"],
        "url": "https://paypa1.example.invalid",
    }
    monkeypatch.setattr(ml_scanner, "analyze_url", lambda _url, model_type="qr": expected)
    app = FastAPI()
    ml_scanner.setup_ml_routes(app)
    response = TestClient(app).post(
        "/ml/analyze/url",
        json={"url": "https://paypa1.example.invalid"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "success": True,
        "risk_score": 0.91,
        "risk_factors": ["Typosquatting: paypa1"],
        "is_suspicious": True,
    }
