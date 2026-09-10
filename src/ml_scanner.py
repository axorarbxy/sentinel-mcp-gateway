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
phishing_model_dir = os.path.join(project_root, 'ml_models', 'phishing_detector', 'models')

print(f"📁 QR models: {model_dir}")
print(f"📁 Phishing models: {phishing_model_dir}")

# Load QR models
try:
    xgb_model = joblib.load(os.path.join(model_dir, 'url_xgb_model.pkl'))
    rf_model = joblib.load(os.path.join(model_dir, 'url_rf_model.pkl'))
    scaler = joblib.load(os.path.join(model_dir, 'url_scaler.pkl'))
    print("✅ QR URL-based ML models loaded")
    MODELS_LOADED = True
except Exception as e:
    print(f"⚠️ Failed to load QR models: {e}")
    MODELS_LOADED = False
    xgb_model = rf_model = scaler = None

# Load Phishing models
try:
    phishing_xgb = joblib.load(os.path.join(phishing_model_dir, 'phishing_xgb.pkl'))
    phishing_rf = joblib.load(os.path.join(phishing_model_dir, 'phishing_rf.pkl'))
    phishing_scaler = joblib.load(os.path.join(phishing_model_dir, 'phishing_scaler.pkl'))
    print("✅ Phishing detection models loaded")
    PHISHING_MODELS_LOADED = True
except Exception as e:
    print(f"⚠️ Failed to load phishing models: {e}")
    PHISHING_MODELS_LOADED = False
    phishing_xgb = phishing_rf = phishing_scaler = None


# ============ KNOWN BENIGN DOMAINS ============
KNOWN_BENIGN_DOMAINS = [
    # Tech
    'google.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
    'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com',
    'linkedin.com', 'reddit.com', 'amazon.com', 'amazon.in', 'apple.com',
    'microsoft.com', 'netflix.com', 'spotify.com', 'python.org',
    'nodejs.org', 'reactjs.org', 'fastapi.tiangolo.com',
    'bing.com', 'duckduckgo.com', 'yahoo.com',
    'ebay.com', 'walmart.com', 'target.com', 'flipkart.com', 'myntra.com',
    # Payments
    'paypal.com', 'pay.google.com',
    # Finance
    'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    'citibank.com', 'capitalone.com', 'coinbase.com', 'binance.com',
    # Messaging
    'whatsapp.com', 'wa.me', 'web.whatsapp.com', 'chat.whatsapp.com',
    'api.whatsapp.com', 'whatsapp.net', 'telegram.org', 't.me',
    'signal.org', 'discord.com', 'discord.gg', 'slack.com',
    'zoom.us', 'meet.google.com', 'teams.microsoft.com',
    # Google Services
    'bit.ly', 'youtu.be', 'goo.gl', 'maps.google.com',
    'drive.google.com', 'docs.google.com', 'sheets.google.com',
    'gmail.com', 'mail.google.com', 'calendar.google.com',
    # Others
    'github.io', 'gitlab.com', 'bitbucket.org', 'notion.so', 'figma.com',
    'dropbox.com', 'box.com', 'mega.nz', 'mediafire.com',
    'booking.com', 'airbnb.com', 'uber.com', 'ola.cab',
    'zomato.com', 'swiggy.com',
    # Security / News / Education
    'netcraft.com', 'kaspersky.com', 'mcafee.com', 'norton.com', 'avast.com',
    'malwarebytes.com', 'sophos.com', 'trendmicro.com', 'fortinet.com',
    'crowdstrike.com', 'paloaltonetworks.com', 'checkpoint.com', 'cisco.com',
    'wired.com', 'theverge.com', 'techcrunch.com', 'arstechnica.com',
    'zdnet.com', 'cnet.com', 'engadget.com', 'bbc.com', 'cnn.com',
    'nytimes.com', 'theguardian.com', 'forbes.com', 'bloomberg.com',
    'medium.com', 'substack.com', 'dev.to', 'hashnode.com',
    'owasp.org', 'sans.org', 'nist.gov', 'cisa.gov', 'mitre.org',
    'hackerone.com', 'bugcrowd.com', 'portswigger.net', 'tryhackme.com',
    'hackthebox.com', 'cybrary.it', 'udemy.com', 'coursera.org',
    'edx.org', 'khanacademy.org', 'w3schools.com', 'mdn.mozilla.org',
    'digitalocean.com', 'aws.amazon.com', 'azure.microsoft.com',
    'cloud.google.com', 'heroku.com', 'vercel.com', 'netlify.com',
    'npmjs.com', 'pypi.org', 'docker.com', 'kubernetes.io',
    'redhat.com', 'ubuntu.com', 'debian.org', 'mozilla.org',
    'cloudflare.com', 'akamai.com', 'fastly.com',
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
    """Extract 26 features from URL"""
    features = []
    
    try:
        url_lower = str(url).lower()
        if not url_lower.startswith(('http://', 'https://')):
            url_lower = 'http://' + url_lower
        
        parsed = urlparse(url_lower)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        features.append(min(len(url_lower) / 100.0, 2.0))
        features.append(min(len(domain) / 50.0, 2.0))
        features.append(min(len(path) / 100.0, 2.0))
        features.append(min(domain.count('.'), 5))
        features.append(max(0, min(domain.count('.') - 1, 5)))
        features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0)
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.site',
                           '.online', '.work', '.click', '.link', '.review', '.country']
        features.append(1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0)
        
        # 8. Phishing keywords — ONLY count if in DOMAIN or as full path segment
        phishing_words = ['login', 'verify', 'secure', 'update', 'confirm', 'account',
                          'banking', 'password', 'credential', 'signin', 'auth', 'recovery',
                          'validation', 'unlock', 'restore', 'suspended']
        keyword_count = 0
        for w in phishing_words:
            if w in domain:
                keyword_count += 2
            elif f'/{w}/' in path or f'/{w}.' in path or path.endswith(f'/{w}'):
                keyword_count += 1
        features.append(min(keyword_count / 3.0, 2.0))
        
        brands = ['paypal', 'google', 'amazon', 'facebook', 'apple', 'microsoft',
                  'netflix', 'instagram', 'whatsapp', 'twitter', 'linkedin',
                  'chase', 'wellsfargo', 'citibank', 'bankofamerica', 'coinbase',
                  'binance', 'metamask', 'blockchain', 'bank']
        brand_count = sum(1 for b in brands if b in url_lower)
        features.append(min(brand_count, 3))
        
        typo_count = sum(1 for c in domain if c in ['0', '1', '3', '4', '5', '7'])
        features.append(min(typo_count / 3.0, 2.0))
        features.append(min(domain.count('-') / 2.0, 2.0))
        
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
                      'shorturl', 'tiny.cc', 'tr.im', 'v.gd', 't.co']
        features.append(1 if any(s in domain for s in shorteners) else 0)
        
        features.append(1 if url_lower.startswith('https') else 0)
        features.append(1 if '@' in url_lower else 0)
        features.append(1 if '//' in url_lower[8:] else 0)
        features.append(min(url_lower.count('=') / 3.0, 2.0))
        features.append(min(url_lower.count('&') / 2.0, 2.0))
        
        url_no_fragment = url_lower.split('#')[0]
        special_count = sum(1 for c in url_no_fragment if c in '!@#$%^&*()')
        features.append(min(special_count / 3.0, 2.0))
        
        if domain:
            domain_chars = Counter(domain)
            entropy = -sum((count/len(domain)) * np.log2(count/len(domain))
                           for count in domain_chars.values())
            features.append(entropy / 5.0)
        else:
            features.append(0)
        
        features.append(min(path.count('/') / 3.0, 2.0))
        features.append(1 if domain.startswith('www.') else 0)
        features.append(1 if domain.count('.') > 3 else 0)
        features.append(1 if any(url_lower.endswith(ext) for ext in
                                 ['.exe', '.zip', '.rar', '.scr', '.apk', '.msi', '.dmg']) else 0)
        
        benign_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co']
        has_suspicious = any(w in url_lower for w in ['verify', 'secure-login', 'account-update'])
        features.append(1 if (any(domain.endswith(tld) for tld in benign_tlds)
                              and not has_suspicious) else 0)
        
        features.append(1 if is_known_benign(domain) else 0)
        
        path_has_brand = any(b in path for b in brands)
        features.append(1 if path_has_brand else 0)
        
    except Exception:
        return np.zeros(26)
    
    return np.array(features, dtype=np.float32)


def analyze_url(url: str, model_type: str = 'qr') -> dict:
    """Analyze URL for phishing"""
    if model_type == 'phishing' and PHISHING_MODELS_LOADED:
        active_xgb = phishing_xgb
        active_rf = phishing_rf
        active_scaler = phishing_scaler
    elif MODELS_LOADED:
        active_xgb = xgb_model
        active_rf = rf_model
        active_scaler = scaler
    else:
        return {
            'is_malicious': False,
            'confidence': 0.5,
            'risk_factors': ['Model not loaded'],
            'url': url
        }
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # ============ KNOWN BENIGN OVERRIDE ============
    try:
        parsed = urlparse(url.lower())
        domain = parsed.netloc.lower()
        
        if is_known_benign(domain):
            print(f"✅ Known benign domain: {domain}")
            return {
                'is_malicious': False,
                'confidence': 0.02,
                'xgb_score': 0.02,
                'rf_score': 0.02,
                'risk_factors': ['✅ Verified official service'],
                'url': url
            }
    except Exception as e:
        print(f"Known benign check error: {e}")
    
    # ============ SMART OVERRIDE: trusted TLD + blog/news path ============
    try:
        parsed = urlparse(url.lower())
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        trusted_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co']
        trusted_paths = ['/blog/', '/news/', '/article/', '/post/', '/docs/', '/wiki/']
        
        is_trusted_tld = any(domain.endswith(tld) for tld in trusted_tlds)
        has_trusted_path = any(p in path for p in trusted_paths)
        
        hard_signals = ['paypa1', 'amaz0n', 'go0gle', 'faceb00k', 'app1e', 'micr0soft',
                       '.tk', '.ml', '.ga', '.cf', '.top', '.xyz']
        has_hard_signal = any(sig in domain for sig in hard_signals)
        
        if is_trusted_tld and has_trusted_path and not has_hard_signal:
            print(f"✅ Trusted TLD + blog/news path: {domain}")
            return {
                'is_malicious': False,
                'confidence': 0.15,
                'xgb_score': 0.15,
                'rf_score': 0.15,
                'risk_factors': ['✅ Trusted domain with content path'],
                'url': url
            }
    except Exception as e:
        print(f"Trusted path check error: {e}")
    
    # ============ ML PREDICTION ============
    try:
        features = extract_url_features(url).reshape(1, -1)
        features_scaled = active_scaler.transform(features)
        
        xgb_prob = float(active_xgb.predict_proba(features_scaled)[0][1])
        rf_prob = float(active_rf.predict_proba(features_scaled)[0][1])
        avg_prob = (xgb_prob + rf_prob) / 2
        
        is_malicious = avg_prob > 0.5
        
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
    if not content:
        return content
    original = str(content)
    cleaned = original.strip()
    url_match = re.search(r'https?://[^\s\'"\]\},]+', cleaned)
    if url_match:
        cleaned = url_match.group(0)
        cleaned = cleaned.rstrip('.,;:)]}')
    else:
        cleaned = re.sub(r'^\d+\s+', '', cleaned)
        cleaned = re.sub(r'\s+Name:.*$', '', cleaned)
        cleaned = re.sub(r',\s*dtype:.*$', '', cleaned)
        cleaned = cleaned.strip().strip("'\"[]")
    print(f"🧹 Original: {original[:100]}")
    print(f"🧹 Cleaned:  {cleaned[:100]}")
    return cleaned


def decode_qr_multi_method(image_np):
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        decoded = pyzbar_decode(image_np)
        if decoded:
            data = decoded[0].data.decode('utf-8')
            print(f"✅ pyzbar: {data[:60]}")
            return data
    except Exception as e:
        print(f"pyzbar error: {e}")
    
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        pil_img = Image.fromarray(image_np)
        decoded = pyzbar_decode(pil_img)
        if decoded:
            data = decoded[0].data.decode('utf-8')
            print(f"✅ pyzbar PIL: {data[:60]}")
            return data
    except Exception:
        pass
    
    try:
        image_bgr = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR) if len(image_np.shape) == 3 else cv2.cvtColor(image_np, cv2.COLOR_GRAY2BGR)
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(image_bgr)
        if data:
            print(f"✅ OpenCV: {data[:60]}")
            return data
    except Exception:
        pass
    
    print("❌ All decoding methods failed")
    return None


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
    @app.post("/ml/scan/qr")
    async def scan_qr(request: ScanRequest) -> ScanResponse:
        try:
            image_data = request.image
            if ',' in image_data:
                image_data = image_data.split(',')[1]
            image_bytes = base64.b64decode(image_data)
            image_pil = Image.open(io.BytesIO(image_bytes))
            if image_pil.mode != 'RGB':
                image_pil = image_pil.convert('RGB')
            image_np = np.array(image_pil)
            print(f"📷 Image: {image_pil.mode} {image_pil.size}")
            
            raw_content = decode_qr_multi_method(image_np)
            if not raw_content:
                return ScanResponse(
                    success=True, is_malicious=False, confidence=0.0,
                    cnn_score=0.0, xgb_score=0.0, ensemble_score=0.0,
                    decoded_content="No QR code found in image",
                    risk_factors=['No QR code detected'], threshold_used=0.5
                )
            
            cleaned_content = clean_decoded_content(raw_content)
            result = analyze_url(cleaned_content, model_type='qr')
            
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
            "status": "healthy" if (MODELS_LOADED or PHISHING_MODELS_LOADED) else "error",
            "qr_models_loaded": MODELS_LOADED,
            "phishing_models_loaded": PHISHING_MODELS_LOADED,
            "message": "ML scanner ready"
        }
    
    @app.post("/ml/analyze/url")
    async def analyze_url_endpoint(request: URLScanRequest) -> URLScanResponse:
        try:
            result = analyze_url(request.url, model_type='phishing')
            return URLScanResponse(
                success=True,
                risk_score=result['confidence'],
                risk_factors=result['risk_factors'],
                is_suspicious=result['is_malicious']
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))