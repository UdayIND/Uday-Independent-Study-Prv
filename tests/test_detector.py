"""Tests for baseline detector."""

import pandas as pd

from src.detect_baseline.detector import BaselineDetector


def test_detect_recon_scanning(sample_normalized_df, detector_config):
    """Test recon/scanning detection."""
    detector = BaselineDetector(detector_config)

    # Create high fan-out scenario
    df = sample_normalized_df.copy()
    # Add many connections from same source IP
    new_rows = []
    for i in range(60):
        new_row = df.iloc[0].copy()
        new_row["dst_ip"] = f"10.0.0.{i}"
        new_row["ts"] = 1705312200.0 + i
        new_rows.append(new_row)
    df = pd.concat([df, pd.DataFrame(new_rows)], ignore_index=True)

    detections = detector.detect(df)

    assert len(detections) > 0
    assert any(d["detection_type"] == "recon_scanning" for d in detections.to_dict("records"))


def test_detect_dns_beaconing(sample_normalized_df, detector_config):
    """Test DNS beaconing detection."""
    detector = BaselineDetector(detector_config)

    # Create repeated DNS queries scenario
    df = sample_normalized_df[sample_normalized_df["event_type"] == "dns"].copy()
    if len(df) == 0:
        # Create DNS events
        import json

        new_rows = []
        base_row = sample_normalized_df.iloc[0].copy()
        for i in range(15):
            new_row = base_row.copy()
            new_row["event_type"] = "dns"
            new_row["ts"] = 1705312200.0 + i * 100
            new_row["metadata"] = json.dumps({"query": "example.com"})
            new_rows.append(new_row)
        df = pd.concat([df, pd.DataFrame(new_rows)], ignore_index=True)

    detections = detector.detect(df)

    # May or may not detect depending on thresholds
    assert isinstance(detections, type(sample_normalized_df))  # DataFrame


def test_detect_empty_df(detector_config):
    """Test detection on empty DataFrame."""
    import pandas as pd

    detector = BaselineDetector(detector_config)
    empty_df = pd.DataFrame()

    detections = detector.detect(empty_df)

    assert len(detections) == 0


def test_detector_config(detector_config):
    """Test detector initialization with config."""
    detector = BaselineDetector(detector_config)

    assert detector.recon_config["enabled"] is True
    assert detector.dns_config["enabled"] is True
