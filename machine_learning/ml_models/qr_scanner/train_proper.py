"""
QR Scanner Training - Memory Safe
Uses subset of Fouad Trad dataset
"""

import numpy as np
import cv2
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, confusion_matrix
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

from load_real_datasets import RealDatasetLoader

MAX_SAMPLES = 2000

class QRCNN(nn.Module):
    def __init__(self):
        super(QRCNN, self).__init__()
        self.conv1 = nn.Conv2d(3, 32, kernel_size=3, stride=2, padding=1)
        self.bn1 = nn.BatchNorm2d(32)
        self.pool1 = nn.MaxPool2d(2, 2)
        self.conv2 = nn.Conv2d(32, 64, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm2d(64)
        self.pool2 = nn.MaxPool2d(2, 2)
        self.conv3 = nn.Conv2d(64, 128, kernel_size=3, padding=1)
        self.bn3 = nn.BatchNorm2d(128)
        self.pool3 = nn.MaxPool2d(2, 2)
        self.conv4 = nn.Conv2d(128, 256, kernel_size=3, padding=1)
        self.bn4 = nn.BatchNorm2d(256)
        self.pool4 = nn.AdaptiveAvgPool2d((1, 1))
        self.fc1 = nn.Linear(256, 128)
        self.dropout1 = nn.Dropout(0.4)
        self.fc2 = nn.Linear(128, 1)
        
    def forward(self, x):
        x = self.pool1(F.relu(self.bn1(self.conv1(x))))
        x = self.pool2(F.relu(self.bn2(self.conv2(x))))
        x = self.pool3(F.relu(self.bn3(self.conv3(x))))
        x = self.pool4(F.relu(self.bn4(self.conv4(x))))
        x = x.view(x.size(0), -1)
        x = F.relu(self.fc1(x))
        x = self.dropout1(x)
        x = torch.sigmoid(self.fc2(x))
        return x

def extract_structural_features(image):
    if len(image.shape) == 3:
        gray = cv2.cvtColor((image * 255).astype(np.uint8), cv2.COLOR_RGB2GRAY)
    else:
        gray = (image * 255).astype(np.uint8)
    
    h, w = gray.shape
    features = []
    features.append(np.mean(gray) / 255.0)
    features.append(np.std(gray) / 255.0)
    edges = cv2.Canny(gray, 50, 150)
    features.append(np.sum(edges > 0) / (h * w))
    left_half = gray[:, :w//2].astype(np.float32)
    right_half = np.fliplr(gray[:, w//2:]).astype(np.float32)
    features.append(np.mean(np.abs(left_half - right_half)) / 255.0)
    binary = (gray < 128).astype(np.uint8)
    features.append(np.sum(binary) / (h * w))
    return np.array(features, dtype=np.float32)

def extract_features_batch(X):
    features = []
    for img in X:
        features.append(extract_structural_features(img))
    return np.array(features)

def train():
    print("\n" + "=" * 70)
    print("  QR SCANNER - MEMORY SAFE TRAINING")
    print(f"  Using {MAX_SAMPLES} samples from Fouad Trad")
    print("=" * 70 + "\n")
    
    os.makedirs('models', exist_ok=True)
    
    loader = RealDatasetLoader()
    X, y = loader.load_all()
    
    if len(X) == 0:
        print("No data loaded!")
        return
    
    if len(X) > MAX_SAMPLES:
        print(f"\nLimiting to {MAX_SAMPLES} samples (from {len(X)})")
        indices = np.random.choice(len(X), MAX_SAMPLES, replace=False)
        X = X[indices]
        y = y[indices]
    
    print(f"\nUsing: {len(X)} samples")
    print(f"   Benign: {sum(1 for yi in y if yi == 0)}")
    print(f"   Malicious: {sum(1 for yi in y if yi == 1)}")
    
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)
    
    del X, y
    
    print(f"\nSplit: Train {len(X_train)}, Val {len(X_val)}, Test {len(X_test)}")
    
    print("\nExtracting structural features...")
    X_train_xgb = extract_features_batch(X_train)
    X_val_xgb = extract_features_batch(X_val)
    X_test_xgb = extract_features_batch(X_test)
    
    scaler = StandardScaler()
    X_train_xgb = scaler.fit_transform(X_train_xgb)
    X_val_xgb = scaler.transform(X_val_xgb)
    X_test_xgb = scaler.transform(X_test_xgb)
    
    print("\nTraining XGBoost...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=50,
        max_depth=4,
        learning_rate=0.1,
        scale_pos_weight=2.0,
        random_state=42,
        verbosity=0,
        n_jobs=1
    )
    xgb_model.fit(X_train_xgb, y_train)
    print("   Done")
    
    print("\nTraining CNN...")
    device = torch.device('cpu')
    
    X_train_t = torch.FloatTensor(X_train).permute(0, 3, 1, 2)
    y_train_t = torch.FloatTensor(y_train).reshape(-1, 1)
    X_val_t = torch.FloatTensor(X_val).permute(0, 3, 1, 2)
    y_val_t = torch.FloatTensor(y_val).reshape(-1, 1)
    
    del X_train, X_val
    
    train_loader = DataLoader(TensorDataset(X_train_t, y_train_t), batch_size=16, shuffle=True)
    val_loader = DataLoader(TensorDataset(X_val_t, y_val_t), batch_size=16, shuffle=False)
    
    model = QRCNN().to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCELoss()
    
    best_acc = 0
    for epoch in range(15):
        model.train()
        for bx, by in train_loader:
            optimizer.zero_grad()
            loss = criterion(model(bx), by)
            loss.backward()
            optimizer.step()
        
        model.eval()
        preds, labels = [], []
        with torch.no_grad():
            for bx, by in val_loader:
                out = model(bx)
                preds.extend((out > 0.5).cpu().numpy().flatten())
                labels.extend(by.cpu().numpy().flatten())
        
        acc = np.mean(np.array(preds) == np.array(labels))
        if acc > best_acc:
            best_acc = acc
            torch.save(model.state_dict(), 'models/best_cnn_model.pth')
        
        if (epoch+1) % 3 == 0:
            print(f"   Epoch {epoch+1}/15 - Val Acc: {acc:.4f}")
    
    model.load_state_dict(torch.load('models/best_cnn_model.pth'))
    print(f"   Done (Best Acc: {best_acc:.4f})")
    
    print("\nEvaluating...")
    
    X_test_t = torch.FloatTensor(X_test).permute(0, 3, 1, 2)
    
    model.eval()
    with torch.no_grad():
        cnn_probs = model(X_test_t).cpu().numpy().flatten()
        cnn_preds = (cnn_probs > 0.5).astype(int)
    
    xgb_probs = xgb_model.predict_proba(X_test_xgb)[:, 1]
    xgb_preds = (xgb_probs > 0.5).astype(int)
    
    ensemble_preds = [1 if (cnn_preds[i] or xgb_preds[i]) else 0 for i in range(len(y_test))]
    
    print(f"\n   CNN:")
    print(f"   Acc: {accuracy_score(y_test, cnn_preds):.4f}, Recall: {recall_score(y_test, cnn_preds):.4f}, Precision: {precision_score(y_test, cnn_preds):.4f}")
    
    print(f"\n   XGBoost:")
    print(f"   Acc: {accuracy_score(y_test, xgb_preds):.4f}, Recall: {recall_score(y_test, xgb_preds):.4f}, Precision: {precision_score(y_test, xgb_preds):.4f}")
    
    print(f"\n   Ensemble:")
    print(f"   Acc: {accuracy_score(y_test, ensemble_preds):.4f}, Recall: {recall_score(y_test, ensemble_preds):.4f}, Precision: {precision_score(y_test, ensemble_preds):.4f}")
    
    cm = confusion_matrix(y_test, ensemble_preds)
    print(f"\n   Confusion Matrix: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")
    
    print("\nSaving models...")
    torch.save(model.state_dict(), 'models/pytorch_cnn_model.pth')
    joblib.dump(xgb_model, 'models/xgb_model.pkl')
    joblib.dump(scaler, 'models/scaler.pkl')
    
    from models.ensemble import QREnsemble
    ensemble = QREnsemble()
    ensemble.cnn_model = model
    ensemble.xgb_model = xgb_model
    joblib.dump(ensemble, 'models/ensemble_model.pkl')
    
    print("\n" + "=" * 70)
    print("  TRAINING COMPLETE!")
    print("=" * 70)

if __name__ == "__main__":
    train()