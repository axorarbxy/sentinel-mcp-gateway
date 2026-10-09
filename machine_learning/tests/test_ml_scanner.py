import base64

import cv2
import numpy as np
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import ml_scanner


@pytest.mark.skipif(not ml_scanner.QR_IMAGE_MODELS_LOADED, reason="QR image models are unavailable")
def test_qr_upload_returns_image_and_url_model_scores():
    qr_image = cv2.QRCodeEncoder_create().encode("https://example.com/account")
    success, encoded = cv2.imencode(".png", qr_image)
    assert success

    app = FastAPI()
    ml_scanner.setup_ml_routes(app)
    response = TestClient(app).post(
        "/ml/scan/qr",
        json={"image": base64.b64encode(encoded.tobytes()).decode("ascii")},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["decoded_content"] == "https://example.com/account"
    assert 0.0 <= result["cnn_score"] <= 1.0
    assert 0.0 <= result["xgb_score"] <= 1.0
    assert result["url_analysis"] is not None
    assert result["experimental_ensemble"] is not None
    assert 0.0 <= result["experimental_ensemble"]["confidence"] <= 1.0
    assert any(signal.startswith("QR image CNN score:") for signal in result["risk_factors"])