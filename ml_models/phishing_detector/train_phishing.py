"""
Phishing URL Detector - Training Script
Uses 4 datasets + explicit benign whitelist to reduce false positives
"""

import numpy as np
import pandas as pd
import os
import json
import joblib
import re
from urllib.parse import urlparse
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, recall_score, precision_score,
                             f1_score, confusion_matrix, roc_auc_score)
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(SCRIPT_DIR, 'data', 'raw')
MODELS_DIR = os.path.join(SCRIPT_DIR, 'models')


def extract_url_features(url):
    """Extract 26 features from a URL"""
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
                           '.online', '.work', '.click', '.link', '.review', '.country',
                           '.gq', '.icu', '.buzz', '.monster', '.rest']
        features.append(1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0)
        
        phishing_words = ['login', 'verify', 'secure', 'update', 'confirm', 'account',
                          'banking', 'password', 'credential', 'signin', 'auth', 'recovery',
                          'validation', 'unlock', 'restore', 'suspended', 'webscr', 'wallet']
        keyword_count = sum(1 for w in phishing_words if w in url_lower)
        features.append(min(keyword_count / 3.0, 2.0))
        
        brands = ['paypal', 'google', 'amazon', 'facebook', 'apple', 'microsoft',
                  'netflix', 'instagram', 'whatsapp', 'twitter', 'linkedin',
                  'chase', 'wellsfargo', 'citibank', 'bankofamerica', 'coinbase',
                  'binance', 'metamask', 'blockchain', 'bank', 'steam', 'dropbox',
                  'adobe', 'yahoo', 'outlook', 'office', 'icloud']
        brand_count = sum(1 for b in brands if b in url_lower)
        features.append(min(brand_count, 3))
        
        typo_count = sum(1 for c in domain if c in ['0', '1', '3', '4', '5', '7'])
        features.append(min(typo_count / 3.0, 2.0))
        features.append(min(domain.count('-') / 2.0, 2.0))
        
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
                      'shorturl', 'tiny.cc', 'tr.im', 'v.gd', 't.co', 'short.link',
                      'rb.gy', 'cutt.ly', 'shorturl.at']
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
                                 ['.exe', '.zip', '.rar', '.scr', '.apk', '.msi',
                                  '.dmg', '.php', '.cgi', '.asp']) else 0)
        
        benign_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co']
        has_suspicious = any(w in url_lower for w in ['verify', 'secure-login', 'account-update'])
        features.append(1 if (any(domain.endswith(tld) for tld in benign_tlds)
                              and not has_suspicious) else 0)
        
        known_benign = ['google.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
                        'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com',
                        'linkedin.com', 'reddit.com', 'amazon.com', 'apple.com',
                        'microsoft.com', 'netflix.com', 'spotify.com', 'python.org',
                        'paypal.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
                        'citibank.com', 'whatsapp.com', 'wa.me', 'zoom.us',
                        'dropbox.com', 'adobe.com', 'yahoo.com', 'outlook.com',
                        'cloudflare.com', 'gstatic.com', 'googleapis.com', 'icloud.com']
        is_known_benign = any(domain == kb or domain.endswith('.' + kb) for kb in known_benign)
        features.append(1 if is_known_benign else 0)
        
        path_has_brand = any(b in path for b in brands)
        features.append(1 if path_has_brand else 0)
        
    except Exception:
        return np.zeros(26)
    
    return np.array(features, dtype=np.float32)


def load_malicious_phish(filepath):
    print(f"📂 Loading malicious_phish.csv...")
    if not os.path.exists(filepath):
        print(f"   ⚠️ Not found")
        return [], []
    
    urls, labels = [], []
    try:
        df = pd.read_csv(filepath)
        print(f"   Total rows: {len(df)}")
        
        for _, row in df.iterrows():
            url = str(row['url']).strip()
            label_str = str(row['type']).lower().strip()
            
            if not url or url == 'nan':
                continue
            
            if label_str == 'benign':
                urls.append(url)
                labels.append(0)
            else:
                urls.append(url)
                labels.append(1)
        
        print(f"   ✅ Loaded {len(urls)} (Benign: {labels.count(0)}, Malicious: {labels.count(1)})")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    return urls, labels


def load_phishstorm(filepath):
    print(f"📂 Loading urlset.csv (PhishStorm)...")
    if not os.path.exists(filepath):
        print(f"   ⚠️ Not found")
        return [], []
    
    urls, labels = [], []
    try:
        df = pd.read_csv(filepath)
        print(f"   Total rows: {len(df)}")
        
        for _, row in df.iterrows():
            url = str(row['domain']).strip()
            label = int(float(row['label']))
            
            if not url or url == 'nan':
                continue
            
            urls.append(url)
            labels.append(label)
        
        print(f"   ✅ Loaded {len(urls)} (Benign: {labels.count(0)}, Phishing: {labels.count(1)})")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    return urls, labels


def load_tranco_benign(filepath, max_samples=50000):
    print(f"📂 Loading top-1m.csv (Tranco, max {max_samples})...")
    if not os.path.exists(filepath):
        print(f"   ⚠️ Not found")
        return [], []
    
    urls, labels = [], []
    try:
        df = pd.read_csv(filepath, header=None, names=['rank', 'domain'], nrows=max_samples)
        
        for _, row in df.iterrows():
            domain = str(row['domain']).strip()
            if domain and domain != 'nan':
                urls.append(f"https://{domain}")
                labels.append(0)
        
        print(f"   ✅ Loaded {len(urls)} benign URLs")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    return urls, labels


def load_ft_dataset(filepath):
    print(f"📂 Loading ft_dataset.json (2026 fine-tuning)...")
    if not os.path.exists(filepath):
        print(f"   ⚠️ Not found")
        return [], []
    
    urls, labels = [], []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    url = data.get('url', '')
                    phish = data.get('phish', 0)
                    if url:
                        urls.append(url)
                        labels.append(int(phish))
                except json.JSONDecodeError:
                    continue
        
        print(f"   ✅ Loaded {len(urls)} (Benign: {labels.count(0)}, Phishing: {labels.count(1)})")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    return urls, labels


def load_all_datasets():
    """Load all datasets + benign whitelist"""
    print("\n" + "=" * 70)
    print("  LOADING ALL PHISHING DATASETS")
    print("=" * 70)
    print(f"\n📁 Data directory: {RAW_DIR}\n")
    
    all_urls = []
    all_labels = []
    
    # 1. Kaggle Malicious URLs
    urls, labels = load_malicious_phish(os.path.join(RAW_DIR, 'malicious_phish.csv'))
    all_urls.extend(urls)
    all_labels.extend(labels)
    
    # 2. PhishStorm
    urls, labels = load_phishstorm(os.path.join(RAW_DIR, 'urlset.csv'))
    all_urls.extend(urls)
    all_labels.extend(labels)
    
    # 3. 2026 Fine-tuning
    urls, labels = load_ft_dataset(os.path.join(RAW_DIR, 'ft_dataset (1).json'))
    all_urls.extend(urls)
    all_labels.extend(labels)
    
    # 4. Tranco benign
    urls, labels = load_tranco_benign(os.path.join(RAW_DIR, 'top-1m.csv'), max_samples=50000)
    all_urls.extend(urls)
    all_labels.extend(labels)
    
    # ============ EXPLICIT BENIGN WHITELIST ============
    print(f"📂 Adding explicit benign whitelist...")
    benign_whitelist = [
        'https://google.com/search', 'https://google.com/maps', 'https://google.com/drive',
        'https://github.com/explore', 'https://github.com/trending',
        'https://stackoverflow.com/questions', 'https://stackoverflow.com/tags',
        'https://wikipedia.org/wiki/Main_Page', 'https://wikipedia.org/wiki/Python',
        'https://youtube.com/watch?v=abc', 'https://youtube.com/feed/subscriptions',
        'https://facebook.com/feed', 'https://facebook.com/profile',
        'https://instagram.com/explore', 'https://instagram.com/p/abc',
        'https://twitter.com/home', 'https://twitter.com/explore',
        'https://linkedin.com/feed', 'https://linkedin.com/jobs',
        'https://reddit.com/r/programming', 'https://reddit.com/r/all',
        'https://amazon.com/products', 'https://amazon.com/orders',
        'https://apple.com/iphone', 'https://apple.com/mac',
        'https://microsoft.com/windows', 'https://microsoft.com/office',
        'https://netflix.com/browse', 'https://netflix.com/title/123',
        'https://spotify.com/discover', 'https://spotify.com/playlist/abc',
        'https://python.org/downloads', 'https://nodejs.org/en',
        'https://reactjs.org/docs', 'https://fastapi.tiangolo.com',
        'https://paypal.com/signin', 'https://paypal.com/myaccount/summary',
        'https://pay.google.com/gp/p/ui/pay', 'https://pay.google.com',
        'https://chase.com/login', 'https://chase.com/personal/checking',
        'https://wellsfargo.com', 'https://wellsfargo.com/account',
        'https://bankofamerica.com', 'https://bankofamerica.com/online-banking',
        'https://citibank.com', 'https://citibank.com/us/personal',
        'https://capitalone.com', 'https://coinbase.com', 'https://binance.com',
        'https://whatsapp.com', 'https://web.whatsapp.com', 'https://wa.me/1234567890',
        'https://telegram.org', 'https://t.me/username',
        'https://signal.org', 'https://discord.com', 'https://discord.gg/abc',
        'https://slack.com', 'https://zoom.us', 'https://meet.google.com/abc-defg-hij',
        'https://teams.microsoft.com',
        'https://drive.google.com/file/d/abc/view', 'https://docs.google.com/document/d/abc',
        'https://sheets.google.com/spreadsheets/d/abc', 'https://gmail.com',
        'https://mail.google.com/mail/u/0/', 'https://calendar.google.com/event',
        'https://github.io', 'https://gitlab.com', 'https://bitbucket.org',
        'https://notion.so', 'https://figma.com', 'https://dropbox.com',
        'https://box.com', 'https://mega.nz', 'https://mediafire.com',
        'https://booking.com', 'https://airbnb.com', 'https://uber.com',
        'https://zomato.com', 'https://swiggy.com', 'https://flipkart.com',
        'https://myntra.com', 'https://amazon.in',
        'https://bing.com', 'https://duckduckgo.com', 'https://yahoo.com',
        'https://ebay.com', 'https://walmart.com', 'https://target.com',
    ]
    
    for url in benign_whitelist:
        all_urls.append(url)
        all_labels.append(0)
    
    print(f"   ✅ Added {len(benign_whitelist)} explicit benign URLs")
    
    print(f"\n📊 Total URLs loaded: {len(all_urls)}")
    print(f"   Benign: {all_labels.count(0)}")
    print(f"   Malicious/Phishing: {all_labels.count(1)}")
    
    return all_urls, all_labels


def train():
    print("\n" + "=" * 70)
    print("  PHISHING URL DETECTOR - TRAINING")
    print("=" * 70 + "\n")
    
    os.makedirs(MODELS_DIR, exist_ok=True)
    print(f"📁 Models will be saved to: {MODELS_DIR}\n")
    
    urls, labels = load_all_datasets()
    
    if len(urls) == 0:
        print("\n❌ No data loaded!")
        return
    
    # Filter
    filtered_urls, filtered_labels = [], []
    for url, label in zip(urls, labels):
        if 3 < len(str(url)) < 2000:
            filtered_urls.append(url)
            filtered_labels.append(label)
    
    print(f"\n📊 After filtering: {len(filtered_urls)} URLs")
    
    # Balance
    benign_count = filtered_labels.count(0)
    malicious_count = filtered_labels.count(1)
    target_per_class = min(benign_count, malicious_count, 300000)
    
    print(f"📊 Balancing to {target_per_class} per class")
    
    balanced_urls, balanced_labels = [], []
    b_added, m_added = 0, 0
    
    for url, label in zip(filtered_urls, filtered_labels):
        if label == 0 and b_added < target_per_class:
            balanced_urls.append(url)
            balanced_labels.append(label)
            b_added += 1
        elif label == 1 and m_added < target_per_class:
            balanced_urls.append(url)
            balanced_labels.append(label)
            m_added += 1
    
    print(f"📊 Balanced: {len(balanced_urls)} URLs")
    print(f"   Benign: {balanced_labels.count(0)}")
    print(f"   Malicious: {balanced_labels.count(1)}")
    
    # Extract features
    print("\n🧠 Extracting URL features...")
    X = []
    batch_size = 5000
    
    for i in range(0, len(balanced_urls), batch_size):
        batch = balanced_urls[i:i+batch_size]
        for url in batch:
            X.append(extract_url_features(url))
        
        if (i // batch_size + 1) % 20 == 0:
            print(f"   Processed {min(i + batch_size, len(balanced_urls))}/{len(balanced_urls)}")
    
    X = np.array(X, dtype=np.float32)
    y = np.array(balanced_labels, dtype=np.int32)
    
    print(f"   ✅ Features shape: {X.shape}")
    
    # Split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )
    
    print(f"\n📊 Data split:")
    print(f"   Train: {len(X_train)}")
    print(f"   Validation: {len(X_val)}")
    print(f"   Test: {len(X_test)}")
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    
    # XGBoost
    print("\n🧠 Training XGBoost...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        verbosity=0,
        n_jobs=-1,
        tree_method='hist'
    )
    xgb_model.fit(X_train_scaled, y_train)
    print("   ✅ XGBoost trained")
    
    # Random Forest
    print("\n🧠 Training Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train_scaled, y_train)
    print("   ✅ Random Forest trained")
    
    # Evaluate
    print("\n" + "=" * 70)
    print("  EVALUATION")
    print("=" * 70)
    
    xgb_preds = xgb_model.predict(X_test_scaled)
    rf_preds = rf_model.predict(X_test_scaled)
    xgb_probs = xgb_model.predict_proba(X_test_scaled)[:, 1]
    rf_probs = rf_model.predict_proba(X_test_scaled)[:, 1]
    ensemble_preds = np.logical_or(xgb_preds, rf_preds).astype(int)
    ensemble_probs = (xgb_probs + rf_probs) / 2
    
    for name, preds in [('XGBoost', xgb_preds), ('Random Forest', rf_preds), ('Ensemble', ensemble_preds)]:
        print(f"\n📊 {name}:")
        print(f"   Accuracy:  {accuracy_score(y_test, preds):.4f}")
        print(f"   Recall:    {recall_score(y_test, preds):.4f}")
        print(f"   Precision: {precision_score(y_test, preds):.4f}")
        print(f"   F1 Score:  {f1_score(y_test, preds):.4f}")
    
    cm = confusion_matrix(y_test, ensemble_preds)
    print(f"\n📊 Confusion Matrix (Ensemble):")
    print(f"   TN: {cm[0][0]}, FP: {cm[0][1]}")
    print(f"   FN: {cm[1][0]}, TP: {cm[1][1]}")
    print(f"\n📊 AUC (Ensemble): {roc_auc_score(y_test, ensemble_probs):.4f}")
    
    # Test examples
    print("\n" + "=" * 70)
    print("  TESTING WITH EXAMPLES")
    print("=" * 70)
    
    test_urls = [
        ('https://google.com/search', 'SAFE'),
        ('https://github.com/explore', 'SAFE'),
        ('https://secure-login.xyz/verify', 'PHISHING'),
        ('https://paypa1-secure.com/update', 'PHISHING'),
        ('https://amaz0n-verify.top/login', 'PHISHING'),
        ('https://paypal.com/signin', 'SAFE'),
        ('https://web.whatsapp.com', 'SAFE'),
        ('https://google.verify-account.tk/login', 'PHISHING'),
    ]
    
    for url, expected in test_urls:
        features = extract_url_features(url).reshape(1, -1)
        features_scaled = scaler.transform(features)
        
        xgb_prob = xgb_model.predict_proba(features_scaled)[0][1]
        rf_prob = rf_model.predict_proba(features_scaled)[0][1]
        avg_prob = (xgb_prob + rf_prob) / 2
        
        result = 'PHISHING' if avg_prob > 0.5 else 'SAFE'
        correct = '✅' if result == expected else '❌'
        print(f"   {correct} {url[:55]:<55} → {result:10s} ({avg_prob*100:.1f}%)")
    
    # Save
    print("\n💾 Saving models...")
    joblib.dump(xgb_model, os.path.join(MODELS_DIR, 'phishing_xgb.pkl'))
    joblib.dump(rf_model, os.path.join(MODELS_DIR, 'phishing_rf.pkl'))
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'phishing_scaler.pkl'))
    print(f"   ✅ Saved to: {MODELS_DIR}")
    
    print("\n" + "=" * 70)
    print("  ✅ TRAINING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    train()