"""
Preprocessing Pipeline for ML Model
Compatible with both training and inference (backend)
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import OrdinalEncoder, RobustScaler
from typing import List, Optional, Dict, Any


class PreprocessingPipeline:
    """
    Unified preprocessing pipeline that can be used during training and inference.
    Handles:
    - Missing values
    - Categorical encoding
    - Feature scaling
    - Feature selection
    """
    
    def __init__(self, num_cols: List[str], cat_cols: List[str], 
                 feature_names: Optional[List[str]] = None):
        self.num_cols = num_cols
        self.cat_cols = cat_cols
        self.feature_names = feature_names
        self.ordinal_encoder = None
        self.scaler = None
        self.is_fitted = False
        
    def fit(self, X: pd.DataFrame):
        """Fit the preprocessing pipeline on training data"""
        # Handle missing values
        X_processed = X.copy()
        
        # Fill missing numeric values with median
        for col in self.num_cols:
            if col in X_processed.columns and X_processed[col].isnull().any():
                X_processed[col].fillna(X_processed[col].median(), inplace=True)
        
        # Fill missing categorical values
        for col in self.cat_cols:
            if col in X_processed.columns and X_processed[col].isnull().any():
                X_processed[col].fillna('unknown', inplace=True)
        
        # Fit ordinal encoder for categoricals
        if self.cat_cols:
            cat_cols_present = [c for c in self.cat_cols if c in X_processed.columns]
            if cat_cols_present:
                self.ordinal_encoder = OrdinalEncoder(
                    handle_unknown='use_encoded_value', 
                    unknown_value=-1
                )
                self.ordinal_encoder.fit(X_processed[cat_cols_present].astype(str))
        
        # Fit scaler for numeric features
        num_cols_present = [c for c in self.num_cols if c in X_processed.columns]
        if num_cols_present:
            self.scaler = RobustScaler()
            self.scaler.fit(X_processed[num_cols_present])
        
        self.is_fitted = True
        return self
    
    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Transform data using fitted pipeline"""
        if not self.is_fitted:
            raise ValueError("Pipeline must be fitted before transform")
        
        X_processed = X.copy()
        
        # Handle missing values
        for col in self.num_cols:
            if col in X_processed.columns:
                if X_processed[col].isnull().any():
                    # Use median from training if available, else 0
                    median_val = X_processed[col].median() if len(X_processed) > 0 else 0
                    X_processed[col].fillna(median_val, inplace=True)
            else:
                # Add missing columns with 0
                X_processed[col] = 0
        
        for col in self.cat_cols:
            if col in X_processed.columns:
                if X_processed[col].isnull().any():
                    X_processed[col].fillna('unknown', inplace=True)
            else:
                # Add missing columns with 'unknown'
                X_processed[col] = 'unknown'
        
        # Encode categoricals
        if self.cat_cols and self.ordinal_encoder is not None:
            cat_cols_present = [c for c in self.cat_cols if c in X_processed.columns]
            if cat_cols_present:
                X_processed[cat_cols_present] = self.ordinal_encoder.transform(
                    X_processed[cat_cols_present].astype(str)
                )
                X_processed[cat_cols_present] = X_processed[cat_cols_present].astype(float)
        
        # Scale numeric features
        num_cols_present = [c for c in self.num_cols if c in X_processed.columns]
        if num_cols_present and self.scaler is not None:
            X_processed[num_cols_present] = self.scaler.transform(X_processed[num_cols_present])
        
        # Select features in the correct order
        if self.feature_names:
            # Ensure all feature names are present
            for feat in self.feature_names:
                if feat not in X_processed.columns:
                    X_processed[feat] = 0
            
            # Select features in the order they were trained
            X_final = X_processed[self.feature_names]
        else:
            # Use all numeric and categorical columns
            all_cols = self.num_cols + self.cat_cols
            X_final = X_processed[[c for c in all_cols if c in X_processed.columns]]
        
        return X_final.values








