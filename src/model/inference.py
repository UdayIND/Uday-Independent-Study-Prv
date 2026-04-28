"""
Model Inference Pipeline.
Loads trained Anomaly Detection models to predict threats on new events.
"""

import logging
from typing import Dict, List, Any

import joblib
import pandas as pd

from src.config import Config
from src.model.train import FeatureExtractor

logger = logging.getLogger(__name__)

class ThreatPredictor:
    def __init__(self):
        model_path = Config.MODEL_SAVE_DIR / f"isolation_forest_v_{Config.MODEL_VERSION}.joblib"
        scaler_path = Config.MODEL_SAVE_DIR / f"scaler_v_{Config.MODEL_VERSION}.joblib"
        
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.ready = True
        except Exception as e:
            logger.error(f"Failed to load model artifacts. Have you run the training script? Error: {e}")
            self.ready = False

    def predict(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict threat likelihood for a list of event dictionaries."""
        if not self.ready:
            raise RuntimeError("Model is not loaded.")
            
        df = pd.DataFrame(events)
        features = FeatureExtractor.extract_features(df)
        
        if features.empty:
            return []
            
        X_scaled = self.scaler.transform(features)
        
        # Isolation Forest returns -1 for anomaly, 1 for normal
        predictions = self.model.predict(X_scaled)
        scores = self.model.decision_function(X_scaled)  # Lower is more anomalous
        
        results = []
        for i, (src_ip, row) in enumerate(features.iterrows()):
            is_threat = bool(predictions[i] == -1)
            # Normalize score slightly for readability: invert so higher is more anomalous
            risk_score = float(-scores[i]) 
            
            results.append({
                "src_ip": src_ip,
                "is_threat": is_threat,
                "risk_score": round(risk_score, 4),
                "metrics": row.to_dict()
            })
            
        return results
