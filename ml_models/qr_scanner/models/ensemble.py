"""
Ensemble Model combining PyTorch CNN and XGBoost
"""

import numpy as np
import joblib
import os
from .cnn_model import QRPyTorchModel
from .xgboost_model import QRXGBoostModel

class QREnsemble:
    """Ensemble model with recall-first strategy"""
    
    def __init__(self, cnn_weight=0.6, xgb_weight=0.4):
        self.cnn_model = None
        self.xgb_model = None
        self.cnn_weight = cnn_weight
        self.xgb_weight = xgb_weight
        self.malicious_threshold = 0.35
        
    def build_models(self):
        self.cnn_model = QRPyTorchModel()
        self.cnn_model.compile()
        self.xgb_model = QRXGBoostModel()
        return self
    
    def train(self, X_train_cnn, y_train_cnn, X_val_cnn, y_val_cnn,
              X_train_xgb, y_train_xgb, X_val_xgb, y_val_xgb):
        print("\n🧠 Training PyTorch CNN...")
        self.cnn_model.train(X_train_cnn, y_train_cnn, X_val_cnn, y_val_cnn, epochs=10)
        
        print("\n🧠 Training XGBoost...")
        self.xgb_model.train(X_train_xgb, y_train_xgb, X_val_xgb, y_val_xgb)
        
        return self
    
    def predict(self, image, structural_features):
        cnn_input = np.expand_dims(image, axis=0)
        cnn_prob = float(self.cnn_model.predict(cnn_input)[0][0])
        
        xgb_input = structural_features.reshape(1, -1)
        xgb_prob = float(self.xgb_model.predict(xgb_input)[0])
        
        ensemble_score = (self.cnn_weight * cnn_prob + self.xgb_weight * xgb_prob)
        
        # High recall: flag if ANY model is suspicious
        cnn_malicious = cnn_prob > 0.4
        xgb_malicious = xgb_prob > 0.3
        ensemble_malicious = ensemble_score > self.malicious_threshold
        
        is_malicious = cnn_malicious or xgb_malicious or ensemble_malicious
        
        risk_factors = []
        if cnn_prob > 0.5:
            risk_factors.append("CNN detected visual anomalies")
        if xgb_prob > 0.5:
            risk_factors.append("Structural pattern analysis indicates risk")
        if ensemble_score > 0.5:
            risk_factors.append("Ensemble confidence score elevated")
        
        return {
            'is_malicious': bool(is_malicious),
            'confidence': max(cnn_prob, xgb_prob, ensemble_score),
            'cnn_score': cnn_prob,
            'xgb_score': xgb_prob,
            'ensemble_score': ensemble_score,
            'risk_factors': risk_factors,
            'threshold_used': self.malicious_threshold
        }
    
    def evaluate(self, X_test_cnn, X_test_xgb, y_test):
        correct = 0
        recall_tp = 0
        recall_fn = 0
        fp = 0
        
        for i in range(len(y_test)):
            result = self.predict(X_test_cnn[i], X_test_xgb[i])
            predicted = 1 if result['is_malicious'] else 0
            actual = y_test[i]
            
            if predicted == actual:
                correct += 1
            if actual == 1 and predicted == 1:
                recall_tp += 1
            if actual == 1 and predicted == 0:
                recall_fn += 1
            if actual == 0 and predicted == 1:
                fp += 1
        
        accuracy = correct / len(y_test)
        recall = recall_tp / (recall_tp + recall_fn) if (recall_tp + recall_fn) > 0 else 0
        precision = recall_tp / (recall_tp + fp) if (recall_tp + fp) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        print("\n" + "=" * 60)
        print("  ENSEMBLE EVALUATION (Recall-First Strategy)")
        print("=" * 60)
        print(f"   Accuracy:          {accuracy:.4f}")
        print(f"   Recall:            {recall:.4f} (Goal: >0.90)")
        print(f"   Precision:         {precision:.4f}")
        print(f"   F1 Score:          {f1:.4f}")
        print(f"   False Negatives:   {recall_fn} (missed malicious)")
        print(f"   False Positives:   {fp} (false alarms)")
        print("=" * 60)
        
        return {
            'accuracy': accuracy,
            'recall': recall,
            'precision': precision,
            'f1': f1,
            'false_negatives': recall_fn,
            'false_positives': fp
        }
    
    def save(self, model_dir='models/'):
        os.makedirs(model_dir, exist_ok=True)
        self.cnn_model.save(f'{model_dir}/pytorch_cnn_model.pth')
        joblib.dump(self.xgb_model.model, f'{model_dir}/xgb_model.pkl')
        joblib.dump(self, f'{model_dir}/ensemble_model.pkl')
        print(f"✅ All models saved to {model_dir}")