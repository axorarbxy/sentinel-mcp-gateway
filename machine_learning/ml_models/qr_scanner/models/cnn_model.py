"""
PyTorch CNN Model for QR Code Malware Detection
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, roc_auc_score

class QRCNN(nn.Module):
    """Lightweight CNN for QR code classification"""
    
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
        self.dropout1 = nn.Dropout(0.3)
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

class QRPyTorchModel:
    """PyTorch model wrapper"""
    
    def __init__(self, device='cpu'):
        self.device = device
        self.model = QRCNN().to(device)
        self.optimizer = None
        self.criterion = nn.BCELoss()
        
    def compile(self, learning_rate=0.001):
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        return self
    
    def train(self, X_train, y_train, X_val, y_val, epochs=10, batch_size=32):
        print(f"   Training CNN for {epochs} epochs...")
        
        X_train_t = torch.FloatTensor(X_train).permute(0, 3, 1, 2).to(self.device)
        y_train_t = torch.FloatTensor(y_train).reshape(-1, 1).to(self.device)
        X_val_t = torch.FloatTensor(X_val).permute(0, 3, 1, 2).to(self.device)
        y_val_t = torch.FloatTensor(y_val).reshape(-1, 1).to(self.device)
        
        train_dataset = TensorDataset(X_train_t, y_train_t)
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        
        for epoch in range(epochs):
            self.model.train()
            epoch_loss = 0
            for batch_x, batch_y in train_loader:
                self.optimizer.zero_grad()
                outputs = self.model(batch_x)
                loss = self.criterion(outputs, batch_y)
                loss.backward()
                self.optimizer.step()
                epoch_loss += loss.item()
            
            if (epoch + 1) % 5 == 0:
                print(f"      Epoch {epoch+1}/{epochs} - Loss: {epoch_loss/len(train_loader):.4f}")
        
        return {'loss': []}
    
    def predict(self, X):
        self.model.eval()
        if isinstance(X, np.ndarray):
            X = torch.FloatTensor(X).permute(0, 3, 1, 2).to(self.device)
        with torch.no_grad():
            outputs = self.model(X)
        return outputs.cpu().numpy()
    
    def evaluate(self, X_test, y_test):
        y_pred_proba = self.predict(X_test)
        y_pred = (y_pred_proba > 0.5).flatten().astype(int)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'f1': f1_score(y_test, y_pred, zero_division=0),
            'auc': roc_auc_score(y_test, y_pred_proba.flatten()) if len(np.unique(y_test)) > 1 else 0.5
        }
        
        print(f"   Accuracy:  {metrics['accuracy']:.4f}")
        print(f"   Recall:    {metrics['recall']:.4f}")
        print(f"   Precision: {metrics['precision']:.4f}")
        print(f"   F1 Score:  {metrics['f1']:.4f}")
        print(f"   AUC:       {metrics['auc']:.4f}")
        
        return metrics
    
    def save(self, path='models/pytorch_cnn_model.pth'):
        torch.save(self.model.state_dict(), path)
        print(f"   ✅ CNN model saved to {path}")