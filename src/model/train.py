"""
Model Training Pipeline.
Trains an Anomaly Detection model (Isolation Forest) on normalized SOC telemetry.
"""

import logging
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.config import Config

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Extracts ML features from raw normalized events."""
    
    @staticmethod
    def extract_features(df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
        
        # Group by source IP and aggregate features
        features = df.groupby('src_ip').agg({
            'event_type': 'count',  # Total events
            'dst_port': 'nunique',  # Unique ports scanned
            'dst_ip': 'nunique',    # Unique hosts targeted
        }).fillna(0)
        
        features.columns = ['total_events', 'unique_dst_ports', 'unique_dst_ips']
        return features

def train_model(data_dir: Path = Path("data/normalized")):
    """Load latest data, train Isolation Forest, and save model artifacts."""
    logger.info(f"Scanning for parquet files in {data_dir}...")
    
    parquet_files = list(data_dir.glob("*.parquet"))
    if not parquet_files:
        logger.warning("No training data found! Please run the ingestion pipeline first.")
        return False
        
    df = pd.concat([pd.read_parquet(f) for f in parquet_files])
    logger.info(f"Loaded {len(df)} total events for training.")
    
    features = FeatureExtractor.extract_features(df)
    if features.empty:
        logger.warning("Extracted features are empty. Aborting training.")
        return False
        
    logger.info(f"Training on {len(features)} unique source IPs...")
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)
    
    # Train model
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X_scaled)
    
    # Save artifacts
    save_path = Config.MODEL_SAVE_DIR / f"isolation_forest_v_{Config.MODEL_VERSION}.joblib"
    scaler_path = Config.MODEL_SAVE_DIR / f"scaler_v_{Config.MODEL_VERSION}.joblib"
    
    joblib.dump(model, save_path)
    joblib.dump(scaler, scaler_path)
    
    logger.info(f"✅ Model saved to {save_path}")
    return True

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_model()
