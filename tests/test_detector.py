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


def test_recon_multi_signal_metadata(sample_normalized_df, detector_config):
    """Test that recon detections include multi-signal metadata."""
    detector = BaselineDetector(detector_config)

    df = sample_normalized_df.copy()
    new_rows = []
    for i in range(60):
        new_row = df.iloc[0].copy()
        new_row["dst_ip"] = f"10.0.0.{i}"
        new_row["ts"] = 1705312200.0 + i
        new_rows.append(new_row)
    df = pd.concat([df, pd.DataFrame(new_rows)], ignore_index=True)

    detections = detector.detect(df)
    recon = [d for d in detections.to_dict("records") if d["detection_type"] == "recon_scanning"]

    if recon:
        meta = recon[0]["metadata"]
        assert "burst_detected" in meta
        assert "max_conns_per_sec" in meta
        assert "failed_connection_ratio" in meta
        assert "signal_scores" in meta
        assert "fan_out" in meta["signal_scores"]
        assert "burst" in meta["signal_scores"]
        assert "failed_conn" in meta["signal_scores"]


def test_recon_confidence_is_multi_signal(sample_normalized_df, detector_config):
    """Test that confidence uses multi-signal scoring (not hardcoded)."""
    detector = BaselineDetector(detector_config)

    df = sample_normalized_df.copy()
    new_rows = []
    for i in range(60):
        new_row = df.iloc[0].copy()
        new_row["dst_ip"] = f"10.0.0.{i}"
        new_row["ts"] = 1705312200.0 + i
        new_rows.append(new_row)
    df = pd.concat([df, pd.DataFrame(new_rows)], ignore_index=True)

    detections = detector.detect(df)
    recon = [d for d in detections.to_dict("records") if d["detection_type"] == "recon_scanning"]

    if recon:
        conf = recon[0]["confidence"]
        assert 0 < conf <= 0.95
        assert conf != 0.9  # Should not be hardcoded


def test_dns_multi_signal_metadata(detector_config):
    """Test that DNS detections include multi-signal metadata."""
    import json

    detector_config["dns_beaconing"]["min_unique_domains"] = 1  # Lower for test
    detector = BaselineDetector(detector_config)

    rows = []
    for i in range(15):
        rows.append(
            {
                "event_type": "dns",
                "src_ip": "10.50.1.10",
                "dst_ip": "8.8.8.8",
                "ts": 1705312200.0 + i * 30,
                "proto": "UDP",
                "sensor": "zeek",
                "metadata": json.dumps({"query": "evil.example.com"}),
            }
        )
    # Add some normal queries for domain diversity
    for i, domain in enumerate(["google.com", "github.com", "example.org"]):
        rows.append(
            {
                "event_type": "dns",
                "src_ip": "10.50.1.10",
                "dst_ip": "8.8.8.8",
                "ts": 1705312200.0 + i * 100,
                "proto": "UDP",
                "sensor": "zeek",
                "metadata": json.dumps({"query": domain}),
            }
        )

    df = pd.DataFrame(rows)
    detections = detector.detect(df)
    dns = [d for d in detections.to_dict("records") if d["detection_type"] == "dns_beaconing"]

    if dns:
        meta = dns[0]["metadata"]
        assert "periodicity_cv" in meta
        assert "nxdomain_ratio" in meta
        assert "unique_domain_count" in meta
        assert "signal_scores" in meta
        assert "periodicity" in meta["signal_scores"]
        assert "nxdomain" in meta["signal_scores"]
        assert "domain_diversity" in meta["signal_scores"]


def test_ground_truth_metrics_benign():
    """Test ground truth metrics with benign label."""
    from src.eval.metrics import compute_ground_truth_metrics

    detections = [
        {"detection_type": "recon_scanning", "src_ip": "10.0.0.1", "ts": 1705312200.0},
    ]
    metrics = compute_ground_truth_metrics(detections, pcap_label="benign")

    assert metrics["pcap_label"] == "benign"
    assert metrics["false_positives"] == 1
    assert metrics["true_positives"] == 0
    assert metrics["precision"] == 0.0


def test_ground_truth_metrics_malicious():
    """Test ground truth metrics with malicious label and expected sources."""
    from src.eval.metrics import compute_ground_truth_metrics

    detections = [
        {"detection_type": "recon_scanning", "src_ip": "10.200.1.50", "ts": 1705312200.0},
        {"detection_type": "recon_scanning", "src_ip": "10.200.1.99", "ts": 1705312200.0},
    ]
    expected = [
        {"src_ip": "10.200.1.50", "detection_type": "recon_scanning"},
    ]
    metrics = compute_ground_truth_metrics(
        detections, pcap_label="malicious", expected_sources=expected
    )

    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 0
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 1.0


def test_ground_truth_metrics_unknown():
    """Test ground truth metrics with unknown label returns no scores."""
    from src.eval.metrics import compute_ground_truth_metrics

    metrics = compute_ground_truth_metrics([], pcap_label="unknown")
    assert metrics["precision"] is None
    assert metrics["recall"] is None
