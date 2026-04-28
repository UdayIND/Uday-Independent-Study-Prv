import pytest
import pandas as pd
from src.model.train import FeatureExtractor

def test_feature_extractor_empty():
    df = pd.DataFrame()
    features = FeatureExtractor.extract_features(df)
    assert features.empty

def test_feature_extractor_valid():
    data = [
        {"src_ip": "192.168.1.1", "event_type": "CONNECT", "dst_port": 80, "dst_ip": "10.0.0.1"},
        {"src_ip": "192.168.1.1", "event_type": "AUTH", "dst_port": 22, "dst_ip": "10.0.0.2"},
        {"src_ip": "10.0.0.5", "event_type": "DNS", "dst_port": 53, "dst_ip": "8.8.8.8"}
    ]
    df = pd.DataFrame(data)
    features = FeatureExtractor.extract_features(df)
    
    assert len(features) == 2
    assert "192.168.1.1" in features.index
    
    row = features.loc["192.168.1.1"]
    assert row["total_events"] == 2
    assert row["unique_dst_ports"] == 2
    assert row["unique_dst_ips"] == 2
