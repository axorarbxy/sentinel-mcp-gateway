"""
QR Code Preprocessing Module
Handles image loading, augmentation, and feature extraction
"""

import numpy as np
import cv2
import pickle
from typing import Tuple, Optional, List
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import os
from PIL import Image

class QRPreprocessor:
    """
    Preprocesses QR code images for CNN and structural feature extraction
    """
    
    def __init__(self, target_size: Tuple[int, int] = (224, 224)):
        self.target_size = target_size
        
    def load_dataset(self, pickle_path: str, img_shape: Tuple[int, int] = (69, 69)) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load dataset from pickle file (GitHub dataset format)
        """
        with open(pickle_path, 'rb') as f:
            data = pickle.load(f)
        
        if len(data.shape) == 3:
            X = data.reshape(data.shape[0], data.shape[1], data.shape[2], 1)
        else:
            X = data
            
        return X, None
    
    def load_pickle_pair(self, images_path: str, labels_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load paired pickle files (images and labels)
        """
        with open(images_path, 'rb') as f:
            X = pickle.load(f)
        with open(labels_path, 'rb') as f:
            y = pickle.load(f)
        return X, y
    
    def preprocess_image(self, image: np.ndarray) -> np.ndarray:
        """
        Preprocess a single image for CNN input
        """
        # Ensure image is uint8
        if image.dtype != np.uint8:
            if image.max() <= 1.0:
                image = (image * 255).astype(np.uint8)
            else:
                image = image.astype(np.uint8)
        
        # Resize
        if image.shape[:2] != self.target_size:
            image = cv2.resize(image, self.target_size)
        
        # Convert to RGB if needed
        if len(image.shape) == 2:
            image = cv2.cvtColor(image, cv2.COLOR_GRAY2RGB)
        elif len(image.shape) == 3 and image.shape[2] == 1:
            image = cv2.cvtColor(image, cv2.COLOR_GRAY2RGB)
        elif len(image.shape) == 3 and image.shape[2] == 4:
            image = cv2.cvtColor(image, cv2.COLOR_RGBA2RGB)
        
        # Normalize to [0, 1]
        image = image.astype(np.float32) / 255.0
        
        return image
    
    def augment_image(self, image: np.ndarray) -> List[np.ndarray]:
        """
        Apply data augmentation for robustness
        """
        if image.dtype != np.uint8:
            if image.max() <= 1.0:
                image = (image * 255).astype(np.uint8)
            else:
                image = image.astype(np.uint8)
        
        augmented = [image]
        
        # Random rotation
        angles = [-15, -5, 5, 15]
        for angle in angles:
            h, w = image.shape[:2]
            M = cv2.getRotationMatrix2D((w//2, h//2), angle, 1.0)
            rotated = cv2.warpAffine(image, M, (w, h))
            augmented.append(rotated)
        
        # Gaussian blur
        for kernel in [(3,3), (5,5)]:
            blurred = cv2.GaussianBlur(image, kernel, 0)
            augmented.append(blurred)
        
        # Brightness variations
        for factor in [0.8, 1.2]:
            bright = np.clip(image * factor, 0, 255).astype(np.uint8)
            augmented.append(bright)
        
        return augmented
    
    def extract_structural_features(self, image: np.ndarray) -> np.ndarray:
        """
        Extract structural features from QR code image
        """
        features = []
        
        # Force convert to uint8
        if image.dtype != np.uint8:
            if image.max() <= 1.0:
                image = (image * 255).astype(np.uint8)
            else:
                image = image.astype(np.uint8)
        
        # Convert to grayscale
        if len(image.shape) == 3:
            gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
        else:
            gray = image
        
        gray = gray.astype(np.uint8)
        h, w = gray.shape
        
        # 1. Basic statistical features
        features.append(float(np.mean(gray)) / 255.0)  # Mean
        features.append(float(np.std(gray)) / 255.0)   # Std dev
        features.append(float(np.min(gray)) / 255.0)   # Min
        features.append(float(np.max(gray)) / 255.0)   # Max
        
        # 2. Edge density
        edges = cv2.Canny(gray, 50, 150)
        edge_density = float(np.sum(edges > 0)) / (h * w)
        features.append(edge_density)
        
        # 3. Symmetry (horizontal)
        left_half = gray[:, :w//2].astype(np.float32)
        right_half = np.fliplr(gray[:, w//2:]).astype(np.float32)
        symmetry = float(np.mean(np.abs(left_half - right_half))) / 255.0
        features.append(symmetry)
        
        # 4. Black/white ratio
        binary = (gray < 128).astype(np.uint8)
        black_ratio = float(np.sum(binary)) / (h * w)
        features.append(black_ratio)
        
        # 5. Finder pattern detection (corners)
        tl = gray[0:h//4, 0:w//4]
        tr = gray[0:h//4, 3*w//4:w]
        bl = gray[3*h//4:h, 0:w//4]
        features.append(float(np.std(tl)) / 255.0)
        features.append(float(np.std(tr)) / 255.0)
        features.append(float(np.std(bl)) / 255.0)
        
        return np.array(features, dtype=np.float32)
    
    def split_data(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Tuple:
        """Split data into train, validation, test sets"""
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
        )
        return X_train, X_val, X_test, y_train, y_val, y_test