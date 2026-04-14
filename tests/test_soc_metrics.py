"""Tests for SOC triage metrics computation."""

import pandas as pd
import pytest

from src.eval.metrics import compute_soc_metrics


@pytest.fixture
def sample_detections():
    """Sample detection list for testing."""
    return [
        {
            "detection_type": "recon_scanning",
            "ts": 1705312200.0,
            "src_ip": "192.168.1.100",
            "confidence": 0.75,
        },
        {
            "detection_type": "recon_scanning",
            "ts": 1705312210.0,
            "src_ip": "192.168.1.100",
            "confidence": 0.70,
        },
        {
            "detection_type": "dns_beaconing",
            "ts": 1705312220.0,
            "src_ip": "192.168.1.101",
            "confidence": 0.65,
        },
        {
            "detection_type": "recon_scanning",
            "ts": 1705312230.0,
            "src_ip": "192.168.1.102",
            "confidence": 0.80,
        },
        {
            "detection_type": "dns_beaconing",
            "ts": 1705312240.0,
            "src_ip": "192.168.1.101",
            "confidence": 0.60,
        },
        {
            "detection_type": "recon_scanning",
            "ts": 1705312250.0,
            "src_ip": "192.168.1.103",
            "confidence": 0.72,
        },
    ]


@pytest.fixture
def sample_cases_with_evidence():
    """Sample cases with structured evidence."""
    return [
        {
            "case_id": "CASE_0001",
            "detection_type": "recon_scanning",
            "evidence": [
                {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "ts": 1705312200.0},
                {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.2", "ts": 1705312201.0},
                {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.3", "ts": 1705312202.0},
            ],
            "validation": {"confidence": 0.8, "is_valid": True},
        },
        {
            "case_id": "CASE_0002",
            "detection_type": "dns_beaconing",
            "evidence": [
                {"src_ip": "192.168.1.101", "dst_ip": "8.8.8.8", "ts": 1705312220.0},
                {"src_ip": "192.168.1.101", "dst_ip": "8.8.8.8", "ts": 1705312250.0},
            ],
            "validation": {"confidence": 0.65, "is_valid": True},
        },
    ]


@pytest.fixture
def sample_normalized_for_soc():
    """Normalized DataFrame spanning 1 hour for FP proxy calculation."""
    n = 100
    data = {
        "ts": [1705312200.0 + i * 36.0 for i in range(n)],  # 100 events over 1 hour
        "sensor": ["zeek"] * 60 + ["suricata"] * 40,
        "event_type": ["conn"] * 50 + ["dns"] * 10 + ["flow"] * 30 + ["alert"] * 10,
        "src_ip": ["192.168.1.100"] * n,
        "dst_ip": [f"10.0.0.{i % 256}" for i in range(n)],
        "src_port": [54321 + i for i in range(n)],
        "dst_port": [80] * 50 + [53] * 10 + [443] * 30 + [22] * 10,
        "proto": ["tcp"] * 80 + ["udp"] * 10 + ["tcp"] * 10,
    }
    return pd.DataFrame(data)


def test_compression_ratio(
    sample_detections, sample_cases_with_evidence, sample_normalized_for_soc
):
    """Test alert-to-case compression ratio."""
    metrics = compute_soc_metrics(
        sample_detections, sample_cases_with_evidence, sample_normalized_for_soc
    )

    # 6 detections / 2 cases = 3.0
    assert metrics["compression_ratio"] == 3.0
    assert metrics["raw_detections"] == 6
    assert metrics["assembled_cases"] == 2


def test_compression_ratio_no_cases(sample_detections, sample_normalized_for_soc):
    """Test compression ratio with zero cases."""
    metrics = compute_soc_metrics(sample_detections, [], sample_normalized_for_soc)

    assert metrics["compression_ratio"] == 0.0
    assert metrics["assembled_cases"] == 0


def test_evidence_completeness_all_valid(
    sample_detections, sample_cases_with_evidence, sample_normalized_for_soc
):
    """Test evidence completeness when all cases have structured evidence."""
    metrics = compute_soc_metrics(
        sample_detections, sample_cases_with_evidence, sample_normalized_for_soc
    )

    # Both cases have evidence with src_ip, so completeness = 1.0
    assert metrics["evidence_completeness"] == 1.0


def test_evidence_completeness_partial():
    """Test evidence completeness when some cases lack structured evidence."""
    detections = [{"detection_type": "test", "ts": 1705312200.0}]
    cases = [
        {
            "case_id": "CASE_0001",
            "evidence": [
                {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "ts": 1705312200.0},
            ],
        },
        {
            "case_id": "CASE_0002",
            "evidence": [{"foo": "bar"}],  # No referenceable fields
        },
        {
            "case_id": "CASE_0003",
            "evidence": [],  # Empty evidence
        },
    ]
    df = pd.DataFrame({"ts": [1705312200.0], "src_ip": ["192.168.1.1"]})

    metrics = compute_soc_metrics(detections, cases, df)

    # Only 1 out of 3 cases has valid evidence
    assert metrics["evidence_completeness"] == pytest.approx(1 / 3)


def test_evidence_completeness_no_cases():
    """Test evidence completeness with zero cases returns None."""
    df = pd.DataFrame({"ts": [1705312200.0]})
    metrics = compute_soc_metrics([], [], df)

    assert metrics["evidence_completeness"] is None


def test_fp_proxy_detections_per_hour(
    sample_detections, sample_cases_with_evidence, sample_normalized_for_soc
):
    """Test FP proxy calculation (detections per hour)."""
    metrics = compute_soc_metrics(
        sample_detections, sample_cases_with_evidence, sample_normalized_for_soc
    )

    # Duration is ~1 hour (100 events * 36s = 3600s), 6 detections
    # fp_proxy = 6 / (3564 / 3600) ~ 6.06
    assert metrics["fp_proxy_detections_per_hour"] > 0
    assert isinstance(metrics["fp_proxy_detections_per_hour"], float)


def test_fp_proxy_single_timestamp():
    """Test FP proxy with a single timestamp (edge case)."""
    detections = [{"detection_type": "test"}]
    cases = []
    df = pd.DataFrame({"ts": [1705312200.0]})

    metrics = compute_soc_metrics(detections, cases, df)

    # Single timestamp means duration=0, should return float(num_detections)
    assert metrics["fp_proxy_detections_per_hour"] == 1.0


def test_fp_proxy_empty_dataframe():
    """Test FP proxy with empty DataFrame."""
    metrics = compute_soc_metrics([], [], pd.DataFrame())

    assert metrics["fp_proxy_detections_per_hour"] == 0.0


def test_fp_proxy_no_ts_column():
    """Test FP proxy when DataFrame has no ts column."""
    detections = [{"detection_type": "test"}, {"detection_type": "test2"}]
    df = pd.DataFrame({"src_ip": ["192.168.1.1", "192.168.1.2"]})

    metrics = compute_soc_metrics(detections, [], df)

    assert metrics["fp_proxy_detections_per_hour"] == 2.0


def test_pcap_label_propagation():
    """Test that pcap_label is correctly propagated."""
    df = pd.DataFrame({"ts": [1705312200.0]})

    metrics_mal = compute_soc_metrics([], [], df, pcap_label="malicious")
    assert metrics_mal["pcap_label"] == "malicious"

    metrics_ben = compute_soc_metrics([], [], df, pcap_label="benign")
    assert metrics_ben["pcap_label"] == "benign"

    metrics_unk = compute_soc_metrics([], [], df)
    assert metrics_unk["pcap_label"] == "unknown"


def test_full_metrics_structure(
    sample_detections, sample_cases_with_evidence, sample_normalized_for_soc
):
    """Test that all expected keys are present in SOC metrics output."""
    metrics = compute_soc_metrics(
        sample_detections,
        sample_cases_with_evidence,
        sample_normalized_for_soc,
        pcap_label="malicious",
    )

    expected_keys = {
        "compression_ratio",
        "raw_detections",
        "assembled_cases",
        "evidence_completeness",
        "pcap_label",
        "fp_proxy_detections_per_hour",
    }

    assert expected_keys == set(metrics.keys())
