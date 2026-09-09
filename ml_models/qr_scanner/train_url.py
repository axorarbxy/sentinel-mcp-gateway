"""
QR Scanner - URL-Based Phishing Detection
This is the ACTUAL working approach - analyze the decoded URL
"""

import numpy as np
import pandas as pd
import pickle
import os
import joblib
import re
from urllib.parse import urlparse
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, confusion_matrix
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')


def extract_url_features(url):
    """Extract features from URL that indicate phishing"""
    features = []
    
    try:
        url_lower = url.lower()
        parsed = urlparse(url_lower)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # 1-3. Length features
        features.append(min(len(url) / 100.0, 2.0))
        features.append(min(len(domain) / 50.0, 2.0))
        features.append(min(len(path) / 100.0, 2.0))
        
        # 4. Dots in domain
        features.append(min(domain.count('.'), 5))
        
        # 5. Subdomains
        features.append(max(0, min(domain.count('.') - 1, 5)))
        
        # 6. IP address in domain
        features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0)
        
        # 7. Suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.site',
                           '.online', '.work', '.click', '.link', '.review', '.country']
        features.append(1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0)
        
        # 8. Phishing keywords
        phishing_words = ['login', 'verify', 'secure', 'update', 'confirm', 'account',
                          'banking', 'password', 'credential', 'signin', 'auth', 'recovery',
                          'validation', 'unlock', 'restore', 'suspended']
        keyword_count = sum(1 for w in phishing_words if w in url_lower)
        features.append(min(keyword_count / 3.0, 2.0))
        
        # 9. Brand names
        brands = ['paypal', 'google', 'amazon', 'facebook', 'apple', 'microsoft',
                  'netflix', 'instagram', 'whatsapp', 'twitter', 'linkedin',
                  'chase', 'wellsfargo', 'citibank', 'bankofamerica', 'coinbase',
                  'binance', 'metamask', 'blockchain', 'bank']
        brand_count = sum(1 for b in brands if b in url_lower)
        features.append(min(brand_count, 3))
        
        # 10. Typosquatting detection (numbers replacing letters)
        typo_count = sum(1 for c in domain if c in ['0', '1', '3', '4', '5', '7'])
        features.append(min(typo_count / 3.0, 2.0))
        
        # 11. Hyphens in domain
        features.append(min(domain.count('-') / 2.0, 2.0))
        
        # 12. URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
                      'shorturl', 'tiny.cc', 'tr.im', 'v.gd', 't.co']
        features.append(1 if any(s in domain for s in shorteners) else 0)
        
        # 13. HTTPS
        features.append(1 if url_lower.startswith('https') else 0)
        
        # 14. @ symbol (obfuscation)
        features.append(1 if '@' in url else 0)
        
        # 15. Double slash in path
        features.append(1 if '//' in url[8:] else 0)
        
        # 16. Query parameters
        features.append(min(url.count('=') / 3.0, 2.0))
        features.append(min(url.count('&') / 2.0, 2.0))
        
        # 17. Special characters
        special_count = sum(1 for c in url if c in '!@#$%^&*()')
        features.append(min(special_count / 3.0, 2.0))
        
        # 18. Domain entropy
        if domain:
            domain_chars = Counter(domain)
            entropy = -sum((count/len(domain)) * np.log2(count/len(domain))
                           for count in domain_chars.values())
            features.append(entropy / 5.0)
        else:
            features.append(0)
        
        # 19. Path depth
        features.append(min(path.count('/') / 3.0, 2.0))
        
        # 20. www present (benign indicator)
        features.append(1 if domain.startswith('www.') else 0)
        
        # 21. Long subdomain chain
        features.append(1 if domain.count('.') > 3 else 0)
        
        # 22. Suspicious extensions
        features.append(1 if any(url_lower.endswith(ext) for ext in
                                 ['.exe', '.zip', '.rar', '.scr', '.apk', '.msi', '.dmg']) else 0)
        
        # 23. Known benign TLD without suspicious keywords
        benign_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io']
        has_suspicious = any(w in url_lower for w in ['verify', 'secure-login', 'account-update'])
        features.append(1 if (any(domain.endswith(tld) for tld in benign_tlds) and not has_suspicious) else 0)
        
        # 24. Is known benign domain?
        known_benign = ['google.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
                        'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com',
                        'linkedin.com', 'reddit.com', 'amazon.com', 'apple.com',
                        'microsoft.com', 'netflix.com', 'spotify.com', 'python.org',
                        'paypal.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
                        'citibank.com', 'whatsapp.com']
        is_known_benign = any(domain == kb or domain.endswith('.' + kb) for kb in known_benign)
        features.append(1 if is_known_benign else 0)
        
        # 25. Path contains brand name (phishing indicator)
        path_has_brand = any(b in path for b in brands)
        features.append(1 if path_has_brand else 0)
        
    except Exception:
        return np.zeros(25)
    
    return np.array(features, dtype=np.float32)


def load_url_data():
    """Load URLs from datasets with real labels"""
    urls = []
    labels = []
    
    # ============ LOAD FROM CIC CSV (REAL LABELS) ============
    csv_path = 'data/real/cic_trap4phish/dataset_batch_1(100).csv'
    if os.path.exists(csv_path):
        print(f"Loading CIC CSV: {csv_path}")
        df = pd.read_csv(csv_path)
        for idx, row in df.iterrows():
            url = str(row['url']).strip()
            label_val = str(row['label']).lower().strip()
            if label_val in ['1', 'phishing', 'malicious', 'bad']:
                urls.append(url)
                labels.append(1)
            elif label_val in ['0', 'safe', 'benign', 'good']:
                urls.append(url)
                labels.append(0)
        print(f"   Loaded {len(urls)} URLs from CIC CSV")
    
    # ============ ADD MORE REAL PHISHING URLS ============
    print("Adding known phishing URL patterns...")
    real_phishing = [
        # Typosquatting
        'https://paypa1.com/login',
        'https://paypa1-secure.com/update',
        'https://paypa1-verify.com/confirm',
        'https://amaz0n.com/account',
        'https://amaz0n-verify.com/login',
        'https://go0gle.com/account',
        'https://faceb00k.com/login',
        'https://micr0soft.com/account',
        'https://app1e.com/verify',
        'https://netfl1x.com/login',
        # Brand in subdomain
        'https://paypal.secure-login.xyz/verify',
        'https://amazon.verify-account.top/confirm',
        'https://apple.verify-id.ml/login',
        'https://google.account-verify.ga/signin',
        'https://microsoft.secure-update.tk/login',
        # Suspicious TLDs
        'https://secure-bank.xyz/login',
        'https://verify-account.tk/confirm',
        'https://account-update.ml/verify',
        'https://banking-secure.ga/login',
        'https://payment-verify.top/confirm',
        # Phishing keywords in URL
        'https://login-verify-secure.com/update',
        'https://confirm-identity.net/verify',
        'https://secure-account.xyz/login',
        'https://verify-payment.tk/confirm',
        'https://update-banking.ga/secure',
        # Long URLs
        'https://a1b2c3d4e5f6.secure-login-verify.tk/account/confirm/user',
        'https://random-string-here.verify-account.ml/login/secure',
        'https://12345678.banking-verify.ga/confirm/identity',
        # IP-based
        'http://192.168.1.1/login',
        'http://10.0.0.1/admin',
        # Special characters
        'https://paypal@secure-login.xyz/verify',
        'https://google%2Ecom.verify.tk/login',
        # File downloads
        'http://download-security-update.xyz/file.exe',
        'https://free-gift-amazon.tk/claim.zip',
        # More phishing patterns
        'https://secure.paypal-login.tk/verify',
        'https://account.google-verify.ml/confirm',
        'https://signin.amazon-account.ga/login',
        'https://verify.microsoft-account.top/confirm',
        'https://appleid.apple-verify.tk/login',
        'https://netflix.account-update.xyz/billing',
        'https://instagram.verify-account.ml/login',
        'https://facebook.secure-login.ga/verify',
        'https://whatsapp.account-verify.tk/confirm',
        'https://twitter.verify-account.top/login',
    ]
    for url in real_phishing:
        urls.append(url)
        labels.append(1)
    
    # ============ ADD MORE REAL BENIGN URLS ============
    print("Adding known benign URL patterns...")
    real_benign = [
        # Popular sites
        'https://google.com/search',
        'https://google.com/maps',
        'https://youtube.com/watch',
        'https://facebook.com/feed',
        'https://instagram.com/explore',
        'https://twitter.com/home',
        'https://linkedin.com/feed',
        'https://reddit.com/r/all',
        'https://wikipedia.org/wiki/Main_Page',
        'https://amazon.com/products',
        'https://apple.com/iphone',
        'https://microsoft.com/windows',
        'https://netflix.com/browse',
        'https://spotify.com/discover',
        'https://github.com/explore',
        'https://stackoverflow.com/questions',
        'https://python.org/downloads',
        'https://nodejs.org/en',
        'https://reactjs.org/docs',
        'https://fastapi.tiangolo.com',
        # Google services
        'https://pay.google.com/gp/p/ui/pay',
        'https://drive.google.com/file/d/abc/view',
        'https://meet.google.com/abc-defg-hij',
        'https://calendar.google.com/event',
        'https://mail.google.com/mail/u/0/',
        'https://maps.google.com/place/12.34,56.78',
        # Real banking
        'https://paypal.com/signin',
        'https://chase.com/login',
        'https://wellsfargo.com',
        'https://bankofamerica.com',
        'https://citibank.com',
        'https://capitalone.com',
        # WhatsApp/Instagram
        'https://whatsapp.com',
        'https://web.whatsapp.com',
        'https://instagram.com',
        'https://facebook.com',
        # More real sites
        'https://www.google.com',
        'https://www.amazon.com',
        'https://www.apple.com',
        'https://www.microsoft.com',
        'https://www.netflix.com',
        'https://www.github.com',
        'https://www.reddit.com',
        'https://www.stackoverflow.com',
        'https://www.wikipedia.org',
        'https://www.youtube.com',
        'https://www.linkedin.com',
        'https://www.twitter.com',
        'https://www.instagram.com',
        'https://www.whatsapp.com',
        'https://www.paypal.com',
    ]
    for url in real_benign:
        urls.append(url)
        labels.append(0)
    
    print(f"\nTotal URLs collected: {len(urls)}")
    print(f"   Benign: {sum(1 for l in labels if l == 0)}")
    print(f"   Malicious: {sum(1 for l in labels if l == 1)}")
    
    return urls, labels


def train():
    print("\n" + "=" * 70)
    print("  QR SCANNER - URL-BASED TRAINING")
    print("  This is the ACTUAL working approach")
    print("=" * 70 + "\n")
    
    os.makedirs('models', exist_ok=True)
    
    # Load URLs
    urls, labels = load_url_data()
    
    print(f"\n📊 Total URLs: {len(urls)}")
    print(f"   Benign: {sum(1 for l in labels if l == 0)}")
    print(f"   Malicious: {sum(1 for l in labels if l == 1)}")
    
    # Extract features
    print("\n🧠 Extracting URL features...")
    X = np.array([extract_url_features(url) for url in urls])
    y = np.array(labels)
    print(f"   Features: {X.shape[1]} per URL")
    
    # Split
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)
    
    print(f"\n📊 Split: Train {len(X_train)}, Val {len(X_val)}, Test {len(X_test)}")
    
    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    
    # Train XGBoost
    print("\n🧠 Training XGBoost...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.05,
        scale_pos_weight=2.0,
        random_state=42,
        verbosity=0
    )
    xgb_model.fit(X_train_scaled, y_train)
    
    # Train Random Forest
    print("🧠 Training Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        class_weight='balanced',
        random_state=42
    )
    rf_model.fit(X_train_scaled, y_train)
    
    # Evaluate
    print("\n📊 Evaluation:")
    
    xgb_preds = xgb_model.predict(X_test_scaled)
    rf_preds = rf_model.predict(X_test_scaled)
    ensemble_preds = [1 if (xgb_preds[i] or rf_preds[i]) else 0 for i in range(len(y_test))]
    
    print(f"\n   XGBoost:")
    print(f"   Acc:       {accuracy_score(y_test, xgb_preds):.4f}")
    print(f"   Recall:    {recall_score(y_test, xgb_preds):.4f}")
    print(f"   Precision: {precision_score(y_test, xgb_preds):.4f}")
    print(f"   F1:        {f1_score(y_test, xgb_preds):.4f}")
    
    print(f"\n   Random Forest:")
    print(f"   Acc:       {accuracy_score(y_test, rf_preds):.4f}")
    print(f"   Recall:    {recall_score(y_test, rf_preds):.4f}")
    print(f"   Precision: {precision_score(y_test, rf_preds):.4f}")
    print(f"   F1:        {f1_score(y_test, rf_preds):.4f}")
    
    print(f"\n   Ensemble:")
    print(f"   Acc:       {accuracy_score(y_test, ensemble_preds):.4f}")
    print(f"   Recall:    {recall_score(y_test, ensemble_preds):.4f}")
    print(f"   Precision: {precision_score(y_test, ensemble_preds):.4f}")
    print(f"   F1:        {f1_score(y_test, ensemble_preds):.4f}")
    
    cm = confusion_matrix(y_test, ensemble_preds)
    print(f"\n   Confusion Matrix:")
    print(f"   TN={cm[0][0]}, FP={cm[0][1]}")
    print(f"   FN={cm[1][0]}, TP={cm[1][1]}")
    
    # Test with examples
    print("\n🧪 Testing with examples:")
    test_urls = [
        ('https://google.com/search?q=test', 0, 'Should be SAFE'),
        ('https://secure-login.xyz/verify', 1, 'Should be MALICIOUS'),
        ('https://amaz0n-verify.top/login', 1, 'Should be MALICIOUS'),
        ('https://github.com/explore', 0, 'Should be SAFE'),
        ('https://paypa1-secure.com/update', 1, 'Should be MALICIOUS'),
        ('https://paypal.com/signin', 0, 'Should be SAFE'),
        ('https://chase.com/login', 0, 'Should be SAFE'),
        ('https://google.verify-account.tk/login', 1, 'Should be MALICIOUS'),
        ('https://web.whatsapp.com', 0, 'Should be SAFE'),
        ('https://appleid.apple-verify.tk/login', 1, 'Should be MALICIOUS'),
    ]
    
    for url, expected, desc in test_urls:
        features = extract_url_features(url).reshape(1, -1)
        features_scaled = scaler.transform(features)
        xgb_prob = xgb_model.predict_proba(features_scaled)[0][1]
        rf_prob = rf_model.predict_proba(features_scaled)[0][1]
        avg_prob = (xgb_prob + rf_prob) / 2
        
        result = "MALICIOUS" if avg_prob > 0.5 else "SAFE"
        correct = "✅" if (result == "MALICIOUS") == (expected == 1) else "❌"
        print(f"   {correct} {url[:55]:<55} → {result:10s} ({avg_prob*100:.1f}%) - {desc}")
    
    # Save
    print("\n💾 Saving models...")
    joblib.dump(xgb_model, 'models/url_xgb_model.pkl')
    joblib.dump(rf_model, 'models/url_rf_model.pkl')
    joblib.dump(scaler, 'models/url_scaler.pkl')
    
    print("\n" + "=" * 70)
    print("  ✅ TRAINING COMPLETE!")
    print("=" * 70)


if __name__ == "__main__":
    train()