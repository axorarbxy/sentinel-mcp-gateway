"""
Real Dataset Loader - ONLY REAL QR CODE DATA
Uses ONLY: Fouad Trad (9,987 labeled QR codes) + CIC CSV (101 labeled URLs)
"""

import os
import numpy as np
import pickle
import cv2
import warnings
warnings.filterwarnings('ignore')

class RealDatasetLoader:
    """Load ONLY real labeled QR code datasets"""
    
    def __init__(self, data_dir=None):
        if data_dir is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            data_dir = os.path.join(current_dir, 'data', 'real')
        self.data_dir = data_dir
        self.X = []
        self.y = []
    
    def load_fouad_trad_dataset(self):
        """Load Fouad Trad dataset - 9,987 QR codes with REAL labels"""
        print("Loading Fouad Trad dataset (9,987 labeled QR codes)...")
        
        pickle_path = os.path.join(self.data_dir, 'fouad_trad', 'qr_codes_29.pickle')
        labels_path = os.path.join(self.data_dir, 'fouad_trad', 'qr_codes_29_labels.pickle')
        
        print(f"   Path: {pickle_path}")
        print(f"   Exists: {os.path.exists(pickle_path)}")
        
        if not os.path.exists(pickle_path):
            print("   Not found")
            return
        
        try:
            with open(pickle_path, 'rb') as f:
                images = pickle.load(f)
            
            with open(labels_path, 'rb') as f:
                labels = pickle.load(f)
            
            print(f"   Found {len(images)} QR codes")
            
            benign = sum(1 for l in labels if l == 0)
            malicious = sum(1 for l in labels if l == 1)
            print(f"   Benign: {benign}, Malicious: {malicious}")
            
            processed = 0
            for i, img in enumerate(images):
                try:
                    if img.dtype == np.uint8:
                        img = img / 255.0
                    
                    if len(img.shape) == 2:
                        img = np.stack([img, img, img], axis=-1)
                    elif len(img.shape) == 3 and img.shape[-1] == 1:
                        img = np.concatenate([img, img, img], axis=-1)
                    elif len(img.shape) == 3 and img.shape[-1] != 3:
                        img = img[:, :, :3]
                    
                    if img.shape[:2] != (224, 224):
                        img = cv2.resize(img, (224, 224))
                    
                    self.X.append(img.astype(np.float32))
                    self.y.append(int(labels[i]))
                    processed += 1
                except Exception:
                    continue
            
            print(f"   Loaded {processed} samples")
            
        except Exception as e:
            print(f"   Error: {e}")
    
    def load_cic_csv(self):
        """Load CIC CSV - 101 URLs with REAL labels"""
        print("Loading CIC CSV (101 labeled URLs)...")
        
        csv_path = os.path.join(self.data_dir, 'cic_trap4phish', 'dataset_batch_1(100).csv')
        
        print(f"   Path: {csv_path}")
        print(f"   Exists: {os.path.exists(csv_path)}")
        
        if not os.path.exists(csv_path):
            print("   Not found")
            return
        
        try:
            import qrcode
            import pandas as pd
            
            df = pd.read_csv(csv_path)
            print(f"   Found {len(df)} URLs")
            print(f"   Label distribution: {df['label'].value_counts().to_dict()}")
            
            processed = 0
            for idx, row in df.iterrows():
                try:
                    url = str(row['url']).strip()
                    if not url or url == 'nan':
                        continue
                    
                    label_val = str(row['label']).lower().strip()
                    if label_val in ['1', 'phishing', 'malicious', 'bad']:
                        label = 1
                    elif label_val in ['0', 'safe', 'benign', 'good']:
                        label = 0
                    else:
                        continue
                    
                    qr = qrcode.QRCode(
                        version=1,
                        box_size=10,
                        border=4,
                        error_correction=qrcode.constants.ERROR_CORRECT_H
                    )
                    qr.add_data(url)
                    qr.make(fit=True)
                    img = qr.make_image(fill_color="black", back_color="white")
                    img = img.resize((224, 224))
                    img_array = np.array(img.convert('RGB')) / 255.0
                    
                    self.X.append(img_array.astype(np.float32))
                    self.y.append(label)
                    processed += 1
                except Exception:
                    continue
            
            print(f"   Generated {processed} QR codes")
            
        except Exception as e:
            print(f"   Error: {e}")
    
    def load_all(self):
        """Load ONLY real labeled QR datasets"""
        print("\n" + "=" * 60)
        print("  LOADING REAL QR CODE DATASETS")
        print("=" * 60 + "\n")
        
        self.X = []
        self.y = []
        
        self.load_fouad_trad_dataset()
        self.load_cic_csv()
        
        print(f"\nTotal loaded: {len(self.X)} samples")
        
        if not self.X:
            return np.array([]), np.array([])
        
        benign = sum(1 for yi in self.y if yi == 0)
        malicious = sum(1 for yi in self.y if yi == 1)
        print(f"   Benign: {benign}")
        print(f"   Malicious: {malicious}")
        
        if benign == 0 or malicious == 0:
            print("ERROR: Only one class!")
            return np.array([]), np.array([])
        
        X = np.array(self.X, dtype=np.float32)
        y = np.array(self.y, dtype=np.int32)
        
        self.X = []
        self.y = []
        
        return X, y