"""
QR Scanner Training Script
"""

import numpy as np
import os
import sys
import qrcode
import random
from PIL import Image

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from preprocess import QRPreprocessor
from models.ensemble import QREnsemble

def generate_synthetic_data(n_samples=1000):
    """Generate synthetic QR code dataset"""
    
    print(f"\n📊 Generating {n_samples} synthetic QR codes...")
    
    X = []
    y = []
    
    # Malicious patterns
    malicious_domains = [
        'secure-login.xyz', 'verify-account.tk', 'banking-update.ml',
        'amaz0n-secure.com', 'paypa1-verify.net', 'apple-security.tk',
        'google-verify.ga', 'microsoft-login.cf', 'facebook-secure.top'
    ]
    
    # Benign domains
    benign_domains = [
        'example.com', 'google.com', 'github.com', 'stackoverflow.com',
        'wikipedia.org', 'python.org', 'microsoft.com', 'apple.com'
    ]
    
    for i in range(n_samples):
        if random.random() > 0.5:
            # Benign URL
            domain = random.choice(benign_domains)
            paths = ['page', 'docs', 'api', 'profile', 'search']
            path = '/'.join(random.sample(paths, 2))
            data = f"https://{domain}/{path}"
            label = 0
        else:
            # Malicious URL
            domain = random.choice(malicious_domains)
            paths = ['login', 'verify', 'update', 'confirm', 'secure']
            path = random.choice(paths)
            data = f"https://{domain}/{path}"
            label = 1
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to numpy array
        img = img.resize((224, 224))
        img_array = np.array(img.convert('RGB'))
        X.append(img_array)
        y.append(label)
        
        if (i + 1) % 500 == 0:
            print(f"   Generated {i+1}/{n_samples}")
    
    X = np.array(X)
    y = np.array(y)
    
    print(f"✅ Generated {len(X)} samples")
    print(f"   Benign: {sum(y==0)}, Malicious: {sum(y==1)}")
    
    return X, y

def main():
    """Main training function"""
    print("\n" + "=" * 60)
    print("  QR SCANNER ML TRAINING")
    print("  PyTorch CNN + XGBoost Ensemble")
    print("=" * 60)
    
    # Create directories
    os.makedirs('models', exist_ok=True)
    
    # Generate data
    X, y = generate_synthetic_data(1000)
    
    # Preprocess
    preprocessor = QRPreprocessor()
    X_train, X_val, X_test, y_train, y_val, y_test = preprocessor.split_data(X, y)
    
    print(f"\n📊 Data Split:")
    print(f"   Train: {len(X_train)}")
    print(f"   Validation: {len(X_val)}")
    print(f"   Test: {len(X_test)}")
    
    # Extract structural features for XGBoost
    print("\n🧠 Extracting structural features...")
    X_train_xgb = np.array([preprocessor.extract_structural_features(img) for img in X_train])
    X_val_xgb = np.array([preprocessor.extract_structural_features(img) for img in X_val])
    X_test_xgb = np.array([preprocessor.extract_structural_features(img) for img in X_test])
    print(f"   Features per image: {X_train_xgb.shape[1]}")
    
    # Train Ensemble
    print("\n" + "=" * 50)
    print("  TRAINING ENSEMBLE MODEL")
    print("=" * 50)
    
    ensemble = QREnsemble(cnn_weight=0.6, xgb_weight=0.4)
    ensemble.build_models()
    ensemble.train(
        X_train, y_train, X_val, y_val,
        X_train_xgb, y_train, X_val_xgb, y_val
    )
    
    # Evaluate
    print("\n" + "=" * 50)
    print("  EVALUATING MODELS")
    print("=" * 50)
    
    print("\n📊 CNN Model:")
    ensemble.cnn_model.evaluate(X_test, y_test)
    
    print("\n📊 XGBoost Model:")
    ensemble.xgb_model.evaluate(X_test_xgb, y_test)
    
    print("\n📊 Ensemble Model:")
    ensemble.evaluate(X_test, X_test_xgb, y_test)
    
    # Save models
    print("\n💾 Saving models...")
    ensemble.save()
    
    print("\n" + "=" * 60)
    print("  ✅ TRAINING COMPLETE!")
    print(f"  Models saved to models/")
    print("=" * 60)

if __name__ == "__main__":
    main()