"""
XGBoost Model for QR Code Feature Analysis
"""

import xgboost as xgb
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, recall_score, precision_score, f1_score

class QRXGBoostModel:
    """XGBoost classifier for structural features"""
    
    def __init__(self):
        self.model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=2.0,
            random_state=42,
            verbosity=0
        )
    
    def train(self, X_train, y_train, X_val=None, y_val=None):
        print("   Training XGBoost...")
        if X_val is not None:
            eval_set = [(X_val, y_val)]
            self.model.fit(X_train, y_train, eval_set=eval_set, verbose=False)
        else:
            self.model.fit(X_train, y_train)
        return self.model
    
    def predict(self, X):
        return self.model.predict_proba(X)[:, 1]
    
    def predict_class(self, X, threshold=0.3):
        probs = self.predict(X)
        return (probs >= threshold).astype(int)
    
    def evaluate(self, X_test, y_test):
        y_pred = self.predict_class(X_test)
        print(f"   Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
        print(f"   Recall:    {recall_score(y_test, y_pred, zero_division=0):.4f}")
        print(f"   Precision: {precision_score(y_test, y_pred, zero_division=0):.4f}")
        print(f"   F1 Score:  {f1_score(y_test, y_pred, zero_division=0):.4f}")
        return {}