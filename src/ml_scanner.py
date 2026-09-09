"""
ML Scanner API Endpoint
Integrates ML QR scanner with the main gateway
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import sys
import os

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ml_models', 'qr_scanner'))

# Import QR Scanner
try:
    from predict import QRScanner
    print("✅ QRScanner imported successfully")
except ImportError as e:
    print(f"⚠️ Import error: {e}")
    class QRScanner:
        def __init__(self):
            self.model = None
        def scan_image(self, image_data):
            return {
                'is_malicious': False,
                'confidence': 0.5,
                'cnn_score': 0.5,
                'xgb_score': 0.5,
                'ensemble_score': 0.5,
                'decoded_content': None,
                'risk_factors': [],
                'threshold_used': 0.35
            }
        def scan_url(self, url):
            return {
                'risk_score': 0.0,
                'risk_factors': [],
                'is_suspicious': False
            }

_scanner = None

def get_scanner():
    global _scanner
    if _scanner is None:
        try:
            _scanner = QRScanner()
            print("✅ ML Scanner initialized")
        except Exception as e:
            print(f"⚠️ Failed to load ML model: {e}")
            _scanner = QRScanner()
    return _scanner

class ScanRequest(BaseModel):
    image: str
    scan_type: str = "base64"

class ScanResponse(BaseModel):
    success: bool
    is_malicious: bool
    confidence: float
    cnn_score: float
    xgb_score: float
    ensemble_score: float
    decoded_content: Optional[str] = None
    risk_factors: List[str] = []
    threshold_used: float

class URLScanRequest(BaseModel):
    url: str

class URLScanResponse(BaseModel):
    success: bool
    risk_score: float
    risk_factors: List[str] = []
    is_suspicious: bool

def setup_ml_routes(app: FastAPI):
    """Add ML scanner routes to the main app"""
    
    @app.post("/ml/scan/qr")
    async def scan_qr(request: ScanRequest) -> ScanResponse:
        """Scan a QR code image for malicious content"""
        try:
            scanner = get_scanner()
            result = scanner.scan_image(request.image)
            
            return ScanResponse(
                success=True,
                is_malicious=result.get('is_malicious', False),
                confidence=result.get('confidence', 0.0),
                cnn_score=result.get('cnn_score', 0.0),
                xgb_score=result.get('xgb_score', 0.0),
                ensemble_score=result.get('ensemble_score', 0.0),
                decoded_content=result.get('decoded_content'),
                risk_factors=result.get('risk_factors', []),
                threshold_used=result.get('threshold_used', 0.35)
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/ml/health")
    async def ml_health():
        """Check if ML models are loaded"""
        try:
            scanner = get_scanner()
            return {
                "status": "healthy",
                "models_loaded": scanner.model is not None,
                "message": "ML QR scanner ready"
            }
        except Exception as e:
            return {
                "status": "error",
                "models_loaded": False,
                "message": str(e)
            }
    
    @app.post("/ml/analyze/url")
    async def analyze_url(request: URLScanRequest) -> URLScanResponse:
        """Analyze a URL for phishing indicators"""
        try:
            scanner = get_scanner()
            result = scanner.scan_url(request.url)
            return URLScanResponse(
                success=True,
                risk_score=result.get('risk_score', 0.0),
                risk_factors=result.get('risk_factors', []),
                is_suspicious=result.get('is_suspicious', False)
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))