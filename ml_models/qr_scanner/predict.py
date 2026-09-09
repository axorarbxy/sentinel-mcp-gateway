"""
QR Scanner Prediction Service
"""

import numpy as np
import cv2
import joblib
import base64
import io
import os
import sys
from PIL import Image
from pyzbar.pyzbar import decode

from preprocess import QRPreprocessor
from models.ensemble import QREnsemble

class QRScanner:
    """ML-powered QR code scanner"""
    
    def __init__(self):
        self.preprocessor = QRPreprocessor()
        self.model = self._load_model()
        
    def _load_model(self):
        """Load the trained ensemble model"""
        # Try multiple possible paths
        possible_paths = [
            'models/ensemble_model.pkl',
            os.path.join(os.path.dirname(__file__), 'models', 'ensemble_model.pkl'),
            os.path.join(os.path.dirname(__file__), '..', 'models', 'ensemble_model.pkl'),
            os.path.join(os.getcwd(), 'ml_models', 'qr_scanner', 'models', 'ensemble_model.pkl'),
        ]
        
        for model_path in possible_paths:
            try:
                if os.path.exists(model_path):
                    print(f"✅ Loading model from: {model_path}")
                    model = joblib.load(model_path)
                    print("✅ ML Model loaded successfully")
                    return model
            except Exception as e:
                print(f"⚠️ Failed to load from {model_path}: {e}")
                continue
        
        print("⚠️ Model not found. Creating new ensemble with untrained models...")
        model = QREnsemble()
        model.build_models()
        
        # Try to load individual models if they exist
        try:
            cnn_path = os.path.join(os.path.dirname(__file__), 'models', 'pytorch_cnn_model.pth')
            if os.path.exists(cnn_path):
                model.cnn_model.load(cnn_path)
                print("✅ CNN model loaded")
        except Exception as e:
            print(f"⚠️ CNN load failed: {e}")
        
        try:
            xgb_path = os.path.join(os.path.dirname(__file__), 'models', 'xgb_model.pkl')
            if os.path.exists(xgb_path):
                model.xgb_model.model = joblib.load(xgb_path)
                print("✅ XGBoost model loaded")
        except Exception as e:
            print(f"⚠️ XGBoost load failed: {e}")
        
        return model
    
    def scan_image(self, image_data) -> dict:
        """
        Scan a QR code image for malicious content
        """
        # Handle different input types
        if isinstance(image_data, str) and image_data.startswith('data:image'):
            # Base64 image from frontend
            try:
                header, data = image_data.split(',', 1)
                image_bytes = base64.b64decode(data)
                image_pil = Image.open(io.BytesIO(image_bytes))
                image = np.array(image_pil)
            except Exception as e:
                print(f"Error decoding base64: {e}")
                return {
                    'decoded_content': None,
                    'is_malicious': False,
                    'confidence': 0.0,
                    'cnn_score': 0.0,
                    'xgb_score': 0.0,
                    'ensemble_score': 0.0,
                    'risk_factors': ['Error decoding image']
                }
        elif isinstance(image_data, np.ndarray):
            image = image_data
        else:
            return {
                'decoded_content': None,
                'is_malicious': False,
                'confidence': 0.0,
                'cnn_score': 0.0,
                'xgb_score': 0.0,
                'ensemble_score': 0.0,
                'risk_factors': ['Unsupported image type']
            }
        
        # Try multiple methods to decode QR code
        decoded_content = None
        
        # Method 1: Direct decode with pyzbar
        try:
            decoded = decode(image)
            if decoded:
                decoded_content = decoded[0].data.decode('utf-8')
                print(f"✅ Method 1 (pyzbar): {decoded_content[:50]}")
        except Exception as e:
            print(f"Method 1 failed: {e}")
        
        # Method 2: Convert to grayscale and try again
        if not decoded_content and len(image.shape) == 3:
            try:
                gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
                decoded = decode(gray)
                if decoded:
                    decoded_content = decoded[0].data.decode('utf-8')
                    print(f"✅ Method 2 (grayscale): {decoded_content[:50]}")
            except Exception as e:
                print(f"Method 2 failed: {e}")
        
        # Method 3: Try with PIL image directly
        if not decoded_content:
            try:
                pil_image = Image.fromarray(image)
                decoded = decode(pil_image)
                if decoded:
                    decoded_content = decoded[0].data.decode('utf-8')
                    print(f"✅ Method 3 (PIL): {decoded_content[:50]}")
            except Exception as e:
                print(f"Method 3 failed: {e}")
        
        # Method 4: Apply preprocessing (enhance contrast, resize, denoise)
        if not decoded_content:
            try:
                # Convert to grayscale
                if len(image.shape) == 3:
                    gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
                else:
                    gray = image
                
                # Enhance contrast
                gray = cv2.equalizeHist(gray)
                
                # Resize if too small
                h, w = gray.shape
                if h < 100 or w < 100:
                    scale = max(200 / h, 200 / w)
                    new_w = int(w * scale)
                    new_h = int(h * scale)
                    gray = cv2.resize(gray, (new_w, new_h), interpolation=cv2.INTER_CUBIC)
                
                # Apply threshold
                _, thresh = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
                
                # Try to decode the preprocessed image
                decoded = decode(thresh)
                if decoded:
                    decoded_content = decoded[0].data.decode('utf-8')
                    print(f"✅ Method 4 (preprocessed): {decoded_content[:50]}")
            except Exception as e:
                print(f"Method 4 failed: {e}")
        
        if not decoded_content:
            decoded_content = 'No QR code found in image'
            print("❌ All decoding methods failed")
        
        # Preprocess for ML (only if QR code was found)
        try:
            processed = self.preprocessor.preprocess_image(image)
            structural_features = self.preprocessor.extract_structural_features(image)
        except Exception as e:
            print(f"Preprocessing error: {e}")
            return {
                'decoded_content': decoded_content,
                'is_malicious': False,
                'confidence': 0.5,
                'cnn_score': 0.5,
                'xgb_score': 0.5,
                'ensemble_score': 0.5,
                'risk_factors': ['Preprocessing error']
            }
        
        # ML Prediction (only if QR code was found and model is available)
        if decoded_content != 'No QR code found in image' and self.model is not None:
            try:
                result = self.model.predict(processed, structural_features)
            except Exception as e:
                print(f"Prediction error: {e}")
                result = {
                    'is_malicious': False,
                    'confidence': 0.5,
                    'cnn_score': 0.5,
                    'xgb_score': 0.5,
                    'ensemble_score': 0.5,
                    'risk_factors': ['Prediction error'],
                    'threshold_used': 0.35
                }
        else:
            # No QR code found or model not available
            result = {
                'is_malicious': False,
                'confidence': 0.0,
                'cnn_score': 0.0,
                'xgb_score': 0.0,
                'ensemble_score': 0.0,
                'risk_factors': ['No QR code detected'] if decoded_content == 'No QR code found in image' else ['Model unavailable'],
                'threshold_used': 0.35
            }
        
        result['decoded_content'] = decoded_content
        
        # If decoded content is a URL, run URL analysis
        if decoded_content and decoded_content != 'No QR code found in image' and decoded_content.startswith(('http://', 'https://')):
            url_analysis = self.scan_url(decoded_content)
            result['url_analysis'] = url_analysis
        
        return result
    
    def scan_url(self, url: str) -> dict:
        """
        Analyze URL for phishing indicators
        """
        import re
        from urllib.parse import urlparse
        
        risk_score = 0.0
        risk_factors = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # 1. Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.site', '.online']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    risk_score += 0.25
                    risk_factors.append(f"Suspicious TLD: {tld}")
            
            # 2. Typosquatting patterns
            common_misspellings = {
                'amaz0n': 'amazon',
                'go0gle': 'google',
                'faceb00k': 'facebook',
                'paypa1': 'paypal',
                'micr0soft': 'microsoft',
                'app1e': 'apple'
            }
            for misspelled, correct in common_misspellings.items():
                if misspelled in domain:
                    risk_score += 0.3
                    risk_factors.append(f"Typosquatting: {misspelled} → {correct}")
            
            # 3. Suspicious keywords
            suspicious_words = ['login', 'verify', 'secure', 'update', 'confirm', 'banking', 'password', 'credential']
            found_words = [w for w in suspicious_words if w in url.lower()]
            if found_words:
                risk_score += 0.15 * len(found_words)
                risk_factors.append(f"Suspicious keywords: {', '.join(found_words)}")
            
            # 4. URL length
            if len(url) > 100:
                risk_score += 0.1
                risk_factors.append("Unusually long URL")
            
            # 5. Redirect patterns
            if '/redirect' in url or '/goto' in url:
                risk_score += 0.2
                risk_factors.append("Redirect pattern detected")
            
            # Normalize
            risk_score = min(risk_score, 1.0)
            
        except Exception as e:
            risk_score = 0.0
            risk_factors = ["URL parsing failed"]
        
        return {
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'is_suspicious': risk_score > 0.4
        }


def scan_qr_from_base64(base64_string):
    """Convenience function for frontend integration"""
    scanner = QRScanner()
    return scanner.scan_image(base64_string)


# For testing
if __name__ == "__main__":
    scanner = QRScanner()
    print("✅ QR Scanner ready")
    print(f"Model loaded: {scanner.model is not None}")