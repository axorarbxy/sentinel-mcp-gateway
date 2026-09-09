"""
ML Scanner API Endpoint
URL-based phishing detection with multi-method QR decoding
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import sys
import os
import base64
import io
import re
import joblib
import numpy as np
import cv2
from PIL import Image
from urllib.parse import urlparse
from collections import Counter

# Paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
model_dir = os.path.join(project_root, 'ml_models', 'qr_scanner', 'models')

print(f"📁 Looking for models in: {model_dir}")

# Load models
try:
    xgb_path = os.path.join(model_dir, 'url_xgb_model.pkl')
    rf_path = os.path.join(model_dir, 'url_rf_model.pkl')
    scaler_path = os.path.join(model_dir, 'url_scaler.pkl')
    
    print(f"   XGB exists: {os.path.exists(xgb_path)}")
    print(f"   RF exists: {os.path.exists(rf_path)}")
    print(f"   Scaler exists: {os.path.exists(scaler_path)}")
    
    xgb_model = joblib.load(xgb_path)
    rf_model = joblib.load(rf_path)
    scaler = joblib.load(scaler_path)
    print("✅ URL-based ML models loaded successfully")
    MODELS_LOADED = True
except Exception as e:
    print(f"⚠️ Failed to load models: {e}")
    import traceback
    traceback.print_exc()
    MODELS_LOADED = False
    xgb_model = rf_model = scaler = None


# ============ KNOWN BENIGN DOMAINS ============
KNOWN_BENIGN_DOMAINS = [
    # Tech
    'google.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
    'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com',
    'linkedin.com', 'reddit.com', 'amazon.com', 'apple.com',
    'microsoft.com', 'netflix.com', 'spotify.com', 'python.org',
    'nodejs.org', 'reactjs.org', 'fastapi.tiangolo.com',
    # Finance
    'paypal.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    'citibank.com', 'capitalone.com', 'coinbase.com', 'binance.com',
    # Messaging
    'whatsapp.com', 'wa.me', 'web.whatsapp.com', 'chat.whatsapp.com',
    'api.whatsapp.com', 'whatsapp.net', 'telegram.org', 't.me',
    'signal.org', 'discord.com', 'discord.gg', 'slack.com',
    # Meetings
    'zoom.us', 'meet.google.com', 'teams.microsoft.com',
    # Google Services
    'bit.ly', 'youtu.be', 'goo.gl', 'maps.google.com',
    'drive.google.com', 'docs.google.com', 'sheets.google.com',
    'gmail.com', 'mail.google.com', 'pay.google.com', 'calendar.google.com',
    # Others
    'github.io', 'gitlab.com', 'bitbucket.org', 'notion.so', 'figma.com',
    'dropbox.com', 'box.com', 'mega.nz', 'mediafire.com',
    'booking.com', 'airbnb.com', 'uber.com', 'ola.cab',
    'zomato.com', 'swiggy.com', 'flipkart.com', 'myntra.com',
]


def is_known_benign(domain):
    """Check if domain is a known benign service"""
    domain = domain.lower().strip()
    if domain.startswith('www.'):
        domain = domain[4:]
    for kb in KNOWN_BENIGN_DOMAINS:
        if domain == kb or domain.endswith('.' + kb):
            return True
    return False


def extract_url_features(url):
    """Extract features from URL"""
    features = []
    
    try:
        url_lower = url.lower()
        parsed = urlparse(url_lower)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Basic features (26 total)
        features.append(min(len(url) / 100.0, 2.0))  # 1
        features.append(min(len(domain) / 50.0, 2.0))  # 2
        features.append(min(len(path) / 100.0, 2.0))  # 3
        features.append(min(domain.count('.'), 5))  # 4
        features.append(max(0, min(domain.count('.') - 1, 5)))  # 5
        features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0)  # 6
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.site',
                           '.online', '.work', '.click', '.link', '.review', '.country']
        features.append(1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0)  # 7
        
        phishing_words = ['login', 'verify', 'secure', 'update', 'confirm', 'account',
                          'banking', 'password', 'credential', 'signin', 'auth', 'recovery',
                          'validation', 'unlock', 'restore', 'suspended']
        keyword_count = sum(1 for w in phishing_words if w in url_lower)
        features.append(min(keyword_count / 3.0, 2.0))  # 8
        
        brands = ['paypal', 'google', 'amazon', 'facebook', 'apple', 'microsoft',
                  'netflix', 'instagram', 'whatsapp', 'twitter', 'linkedin',
                  'chase', 'wellsfargo', 'citibank', 'bankofamerica', 'coinbase',
                  'binance', 'metamask', 'blockchain', 'bank']
        brand_count = sum(1 for b in brands if b in url_lower)
        features.append(min(brand_count, 3))  # 9
        
        typo_count = sum(1 for c in domain if c in ['0', '1', '3', '4', '5', '7'])
        features.append(min(typo_count / 3.0, 2.0))  # 10
        
        features.append(min(domain.count('-') / 2.0, 2.0))  # 11
        
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
                      'shorturl', 'tiny.cc', 'tr.im', 'v.gd', 't.co']
        features.append(1 if any(s in domain for s in shorteners) else 0)  # 12
        
        features.append(1 if url_lower.startswith('https') else 0)  # 13
        features.append(1 if '@' in url else 0)  # 14
        features.append(1 if '//' in url[8:] else 0)  # 15
        features.append(min(url.count('=') / 3.0, 2.0))  # 16
        features.append(min(url.count('&') / 2.0, 2.0))  # 17
        
        # Only count special chars in URL (not fragment)
        url_no_fragment = url.split('#')[0]
        special_count = sum(1 for c in url_no_fragment if c in '!@#$%^&*()')
        features.append(min(special_count / 3.0, 2.0))  # 18
        
        if domain:
            domain_chars = Counter(domain)
            entropy = -sum((count/len(domain)) * np.log2(count/len(domain))
                           for count in domain_chars.values())
            features.append(entropy / 5.0)  # 19
        else:
            features.append(0)
        
        features.append(min(path.count('/') / 3.0, 2.0))  # 20
        features.append(1 if domain.startswith('www.') else 0)  # 21
        features.append(1 if domain.count('.') > 3 else 0)  # 22
        features.append(1 if any(url_lower.endswith(ext) for ext in
                                 ['.exe', '.zip', '.rar', '.scr', '.apk', '.msi', '.dmg']) else 0)  # 23
        
        benign_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io']
        has_suspicious = any(w in url_lower for w in ['verify', 'secure-login', 'account-update'])
        features.append(1 if (any(domain.endswith(tld) for tld in benign_tlds) and not has_suspicious) else 0)  # 24
        
        # Known benign check
        features.append(1 if is_known_benign(domain) else 0)  # 25
        
        path_has_brand = any(b in path for b in brands)
        features.append(1 if path_has_brand else 0)  # 26
        
    except Exception:
        return np.zeros(26)
    
    return np.array(features, dtype=np.float32)


def analyze_url(url: str) -> dict:
    """Analyze URL for phishing"""
    if not MODELS_LOADED:
        return {
            'is_malicious': False,
            'confidence': 0.5,
            'risk_factors': ['Model not loaded'],
            'url': url
        }
    
    # Ensure URL starts with http
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Parse domain
        parsed = urlparse(url.lower())
        domain = parsed.netloc.lower()
        
        # Check if known benign FIRST
        if is_known_benign(domain):
            print(f"✅ Known benign domain: {domain}")
            return {
                'is_malicious': False,
                'confidence': 0.02,  # Very low suspicion
                'xgb_score': 0.02,
                'rf_score': 0.02,
                'risk_factors': ['✅ Verified official service'],
                'url': url
            }
        
        # Run ML prediction
        features = extract_url_features(url).reshape(1, -1)
        features_scaled = scaler.transform(features)
        
        xgb_prob = float(xgb_model.predict_proba(features_scaled)[0][1])
        rf_prob = float(rf_model.predict_proba(features_scaled)[0][1])
        avg_prob = (xgb_prob + rf_prob) / 2
        
        is_malicious = avg_prob > 0.5
        
        # Build risk factors
        risk_factors = []
        url_lower = url.lower()
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                risk_factors.append(f"Suspicious TLD: {tld}")
        
        phishing_words = ['login', 'verify', 'secure', 'update', 'confirm', 'account']
        found = [w for w in phishing_words if w in url_lower]
        if found:
            risk_factors.append(f"Phishing keywords: {', '.join(found)}")
        
        typo_patterns = ['paypa1', 'amaz0n', 'go0gle', 'faceb00k', 'app1e', 'micr0soft']
        for typo in typo_patterns:
            if typo in url_lower:
                risk_factors.append(f"Typosquatting: {typo}")
                break
        
        if not risk_factors:
            risk_factors = ['No obvious threats detected']
        
        return {
            'is_malicious': is_malicious,
            'confidence': avg_prob,
            'xgb_score': xgb_prob,
            'rf_score': rf_prob,
            'risk_factors': risk_factors,
            'url': url
        }
    except Exception as e:
        return {
            'is_malicious': False,
            'confidence': 0.5,
            'risk_factors': [f'Error: {str(e)}'],
            'url': url
        }


def clean_decoded_content(content):
    """Clean QR-decoded content to extract actual URL"""
    if not content:
        return content
    
    original = str(content)
    cleaned = original.strip()
    
    # Extract URL using regex
    url_match = re.search(r'https?://[^\s\'"\]\},]+', cleaned)
    if url_match:
        cleaned = url_match.group(0)
        cleaned = cleaned.rstrip('.,;:)]}')
    else:
        # Remove pandas artifacts
        cleaned = re.sub(r'^\d+\s+', '', cleaned)
        cleaned = re.sub(r'\s+Name:.*$', '', cleaned)
        cleaned = re.sub(r',\s*dtype:.*$', '', cleaned)
        cleaned = cleaned.strip().strip("'\"[]")
    
    print(f"🧹 Original: {original[:100]}")
    print(f"🧹 Cleaned:  {cleaned[:100]}")
    
    return cleaned


def decode_qr_multi_method(image_np):
    """Try multiple methods to decode QR code"""
    
    # Method 1: pyzbar with numpy
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        decoded = pyzbar_decode(image_np)
        if decoded:
            data = decoded[0].data.decode('utf-8')
            print(f"✅ pyzbar (numpy): {data[:60]}")
            return data
    except Exception as e:
        print(f"pyzbar numpy error: {e}")
    
    # Method 2: pyzbar with PIL
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        pil_img = Image.fromarray(image_np)
        decoded = pyzbar_decode(pil_img)
        if decoded:
            data = decoded[0].data.decode('utf-8')
            print(f"✅ pyzbar (PIL): {data[:60]}")
            return data
    except Exception as e:
        print(f"pyzbar PIL error: {e}")
    
    # Method 3: pyzbar with grayscale
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        gray = cv2.cvtColor(image_np, cv2.COLOR_RGB2GRAY) if len(image_np.shape) == 3 else image_np
        decoded = pyzbar_decode(gray)
        if decoded:
            data = decoded[0].data.decode('utf-8')
            print(f"✅ pyzbar (gray): {data[:60]}")
            return data
    except Exception as e:
        print(f"pyzbar gray error: {e}")
    
    # Method 4: OpenCV
    try:
        image_bgr = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR) if len(image_np.shape) == 3 else cv2.cvtColor(image_np, cv2.COLOR_GRAY2BGR)
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(image_bgr)
        if data:
            print(f"✅ OpenCV: {data[:60]}")
            return data
    except Exception as e:
        print(f"OpenCV error: {e}")
    
    # Method 5: Resize and retry
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        h, w = image_np.shape[:2]
        if h < 300 or w < 300:
            scale = max(300/h, 300/w)
            resized = cv2.resize(image_np, (int(w*scale), int(h*scale)))
            decoded = pyzbar_decode(resized)
            if decoded:
                data = decoded[0].data.decode('utf-8')
                print(f"✅ pyzbar (resized): {data[:60]}")
                return data
    except Exception as e:
        print(f"pyzbar resize error: {e}")
    
    print("❌ All decoding methods failed")
    return None


# Pydantic models
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
    threshold_used: float = 0.5

class URLScanRequest(BaseModel):
    url: str

class URLScanResponse(BaseModel):
    success: bool
    risk_score: float
    risk_factors: List[str] = []
    is_suspicious: bool


def setup_ml_routes(app: FastAPI):
    """Add ML scanner routes"""
    
    @app.post("/ml/scan/qr")
    async def scan_qr(request: ScanRequest) -> ScanResponse:
        """Scan a QR code image"""
        try:
            # Decode base64 image
            image_data = request.image
            if ',' in image_data:
                image_data = image_data.split(',')[1]
            
            image_bytes = base64.b64decode(image_data)
            image_pil = Image.open(io.BytesIO(image_bytes))
            
            if image_pil.mode != 'RGB':
                image_pil = image_pil.convert('RGB')
            
            image_np = np.array(image_pil)
            print(f"📷 Image: {image_pil.mode} {image_pil.size}")
            
            # Decode QR
            raw_content = decode_qr_multi_method(image_np)
            
            if not raw_content:
                return ScanResponse(
                    success=True,
                    is_malicious=False,
                    confidence=0.0,
                    cnn_score=0.0,
                    xgb_score=0.0,
                    ensemble_score=0.0,
                    decoded_content="No QR code found in image",
                    risk_factors=['No QR code detected'],
                    threshold_used=0.5
                )
            
            # Clean decoded content
            cleaned_content = clean_decoded_content(raw_content)
            
            # Analyze URL
            result = analyze_url(cleaned_content)
            
            return ScanResponse(
                success=True,
                is_malicious=result['is_malicious'],
                confidence=result['confidence'],
                cnn_score=result.get('rf_score', 0.0),
                xgb_score=result.get('xgb_score', 0.0),
                ensemble_score=result['confidence'],
                decoded_content=cleaned_content,
                risk_factors=result['risk_factors'],
                threshold_used=0.5
            )
            
        except Exception as e:
            print(f"❌ Scan error: {e}")
            import traceback
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/ml/health")
    async def ml_health():
        return {
            "status": "healthy" if MODELS_LOADED else "error",
            "models_loaded": MODELS_LOADED,
            "model_type": "URL-based phishing detection",
            "message": "ML QR scanner ready" if MODELS_LOADED else "Models not loaded"
        }
    
    @app.post("/ml/analyze/url")
    async def analyze_url_endpoint(request: URLScanRequest) -> URLScanResponse:
        try:
            result = analyze_url(request.url)
            return URLScanResponse(
                success=True,
                risk_score=result['confidence'],
                risk_factors=result['risk_factors'],
                is_suspicious=result['is_malicious']
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))