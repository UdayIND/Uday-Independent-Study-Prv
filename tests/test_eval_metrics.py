"""Tests for evaluation metrics computation."""

import json

import pandas as pd
import pytest

from src.eval.metrics import (
    compute_agentic_metrics,
    compute_data_health_metrics,
    compute_detection_quality_metrics,
)


@pytest.fixture
def sample_normalized_df():
    """Create a sample normalized DataFrame for testing."""
    data = {
        "ts": [1609459200, 1609459260, 1609459320, 1609459380],
        "sensor": ["zeek", "zeek", "suricata", "zeek"],
        "event_type": ["conn", "conn", "alert", "dns"],
        "src_ip": ["192.168.1.1", "192.168.1.1", "10.0.0.1", "192.168.1.2"],
        "dst_ip": ["10.0.0.1", "10.0.0.2", "192.168.1.1", "8.8.8.8"],
        "src_port": [12345, 12346, None, 53],
        "dst_port": [80, 443, None, 53],
        "proto": ["tcp", "tcp", "tcp", "udp"],
        "severity": [None, None, "high", None],
        "signature": [None, None, "ET MALWARE", None],
        "metadata": [
            None,
            None,
            json.dumps({"alert": {"signature": "ET MALWARE"}}),
            json.dumps({"query": "example.com", "rcode": "NOERROR"}),
        ],
    }
    return pd.DataFrame(data)


@pytest.fixture
def sample_detections():
    """Create sample detections for testing."""
    return [
        {
            "detection_type": "recon_scanning",
            "src_ip": "192.168.1.1",
            "ts": 1609459200,
            "confidence": 0.7,
        },
        {
            "detection_type": "dns_beaconing",
            "src_ip": "192.168.1.2",
            "ts": 1609459320,
            "confidence": 0.8,
        },
    ]


@pytest.fixture
def sample_cases():
    """Create sample cases for testing."""
    return [
        {
            "case_id": "case_1",
            "detection_type": "recon_scanning",
            "evidence": [{"ts": 1609459200}, {"ts": 1609459260}],
            "validation": {"confidence": 0.7, "is_valid": True},
        },
        {
            "case_id": "case_2",
            "detection_type": "dns_beaconing",
            "evidence": [{"ts": 1609459320}],
            "validation": {"confidence": 0.8, "is_valid": True},
        },
    ]


def test_compute_data_health_metrics_non_empty(sample_normalized_df):
    """Test data health metrics computation with non-empty DataFrame."""
    metrics = compute_data_health_metrics(sample_normalized_df)

    assert metrics["total_events"] == 4
    assert "sensor_counts" in metrics
    assert "event_type_counts" in metrics
    assert "missing_value_rates" in metrics
    assert "timestamp_range" in metrics
    assert "top_src_ips" in metrics
    assert "top_dst_ips" in metrics
    assert "top_ports" in metrics
    assert "dns_stats" in metrics
    assert "suricata_stats" in metrics

    # Check sensor counts
    assert metrics["sensor_counts"]["zeek"] == 3
    assert metrics["sensor_counts"]["suricata"] == 1

    # Check event type counts
    assert metrics["event_type_counts"]["conn"] == 2
    assert metrics["event_type_counts"]["alert"] == 1
    assert metrics["event_type_counts"]["dns"] == 1


def test_compute_data_health_metrics_empty():
    """Test data health metrics computation with empty DataFrame."""
    empty_df = pd.DataFrame()
    metrics = compute_data_health_metrics(empty_df)

    assert metrics["total_events"] == 0
    assert metrics["sensor_counts"] == {}
    assert metrics["event_type_counts"] == {}
    assert metrics["top_src_ips"] == []
    assert metrics["top_dst_ips"] == []
    assert metrics["top_ports"] == []


def test_compute_detection_quality_metrics(sample_detections, sample_cases):
    """Test detection quality metrics computation."""
    metrics = compute_detection_quality_metrics(
        sample_detections, sample_cases, min_evidence_rows=1
    )

    assert metrics["total_detections"] == 2
    assert "detections_by_type" in metrics
    assert "detection_timeline" in metrics
    assert "case_evidence_stats" in metrics
    assert "confidence_stats" in metrics
    assert "explainability_score" in metrics

    # Check detections by type
    assert metrics["detections_by_type"]["recon_scanning"] == 1
    assert metrics["detections_by_type"]["dns_beaconing"] == 1

    # Check explainability (both cases have >= 1 evidence row)
    assert metrics["explainability_score"] == 1.0


def test_compute_detection_quality_metrics_empty():
    """Test detection quality metrics with empty inputs."""
    metrics = compute_detection_quality_metrics([], [], min_evidence_rows=5)

    assert metrics["total_detections"] == 0
    assert metrics["detections_by_type"] == {}
    assert metrics["explainability_score"] == 0.0


def test_compute_agentic_metrics(tmp_path):
    """Test agentic metrics computation from trace file."""
    trace_file = tmp_path / "agent_trace.jsonl"
    trace_content = [
        '{"agent": "orchestrator", "step": "start", "data": {"detection_count": 2}}',
        '{"agent": "triage_agent", "step": "start", "data": {}}',
        '{"agent": "triage_agent", "step": "complete", "data": {"case_count": 2}}',
        '{"agent": "evidence_agent", "step": "start", "data": {}}',
        '{"agent": "evidence_agent", "step": "complete", "data": {"cases_processed": 2}}',
        '{"agent": "critic_agent", "step": "start", "data": {}}',
        '{"agent": "critic_agent", "step": "complete", "data": {"cases_validated": 2}}',
        '{"agent": "report_agent", "step": "start", "data": {}}',
        '{"agent": "report_agent", "step": "complete", "data": {"reports_generated": 2}}',
    ]
    with open(trace_file, "w") as f:
        f.write("\n".join(trace_content))

    metrics = compute_agentic_metrics(str(trace_file))

    assert metrics["critic_checks_passed"] == 2
    assert metrics["evidence_retrieval_passes"] == 1
    assert len(metrics["agent_steps"]) == 9


def test_compute_agentic_metrics_missing_file():
    """Test agentic metrics with missing trace file."""
    metrics = compute_agentic_metrics("/nonexistent/file.jsonl")

    assert metrics["critic_checks_passed"] == 0
    assert metrics["evidence_retrieval_passes"] == 0
    assert metrics["agent_steps"] == []
