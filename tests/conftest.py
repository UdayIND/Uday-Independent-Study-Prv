"""Pytest configuration and fixtures."""

import json
import tempfile
from pathlib import Path

import pandas as pd
import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_zeek_conn_log(temp_dir):
    """Create a sample Zeek conn.log file."""
    log_file = temp_dir / "conn.log"

    sample_events = [
        {
            "ts": 1705312200.0,
            "uid": "C12345",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 54321,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 80,
            "proto": "tcp",
            "duration": 1.5,
            "orig_bytes": 100,
            "resp_bytes": 200,
        },
        {
            "ts": 1705312201.0,
            "uid": "C12346",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 54322,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "duration": 2.0,
            "orig_bytes": 150,
            "resp_bytes": 300,
        },
    ]

    with open(log_file, "w") as f:
        for event in sample_events:
            f.write(json.dumps(event) + "\n")

    return log_file


@pytest.fixture
def sample_zeek_dns_log(temp_dir):
    """Create a sample Zeek dns.log file."""
    log_file = temp_dir / "dns.log"

    sample_events = [
        {
            "ts": 1705312200.0,
            "uid": "C12345",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 54321,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "query": "example.com",
            "qtype": 1,
            "qclass": 1,
            "answers": ["93.184.216.34"],
        },
    ]

    with open(log_file, "w") as f:
        for event in sample_events:
            f.write(json.dumps(event) + "\n")

    return log_file


@pytest.fixture
def sample_suricata_eve_json(temp_dir):
    """Create a sample Suricata eve.json file."""
    log_file = temp_dir / "eve.json"

    sample_events = [
        {
            "timestamp": "2024-01-15T10:30:00.123456+0000",
            "event_type": "flow",
            "src_ip": "192.168.1.100",
            "src_port": 54321,
            "dest_ip": "10.0.0.1",
            "dest_port": 80,
            "proto": "TCP",
            "flow_id": 12345,
        },
        {
            "timestamp": "2024-01-15T10:30:01.123456+0000",
            "event_type": "alert",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2000001,
                "rev": 1,
                "signature": "ET SCAN Potential SSH Scan",
                "category": "Attempted Information Leak",
                "severity": 2,
            },
            "src_ip": "192.168.1.100",
            "src_port": 54322,
            "dest_ip": "10.0.0.2",
            "dest_port": 22,
            "proto": "TCP",
            "flow_id": 12346,
        },
    ]

    with open(log_file, "w") as f:
        for event in sample_events:
            f.write(json.dumps(event) + "\n")

    return log_file


@pytest.fixture
def sample_normalized_df():
    """Create a sample normalized events DataFrame."""
    data = {
        "ts": [1705312200.0, 1705312201.0, 1705312202.0],
        "sensor": ["zeek", "zeek", "suricata"],
        "event_type": ["conn", "dns", "alert"],
        "src_ip": ["192.168.1.100", "192.168.1.100", "192.168.1.100"],
        "dst_ip": ["10.0.0.1", "8.8.8.8", "10.0.0.2"],
        "src_port": [54321, 54322, 54323],
        "dst_port": [80, 53, 22],
        "proto": ["tcp", "udp", "tcp"],
        "uid": ["C12345", "C12346", None],
        "flow_id": [None, None, 12347],
        "severity": [None, None, 2],
        "signature": [None, None, "ET SCAN Potential SSH Scan"],
        "metadata": ['{"duration": 1.5}', '{"query": "example.com"}', '{"alert": {...}}'],
        "case_id": [None, None, None],
    }
    return pd.DataFrame(data)


@pytest.fixture
def sample_detections_df():
    """Create a sample detections DataFrame."""
    data = {
        "detection_type": ["recon_scanning", "dns_beaconing"],
        "ts": [1705312200.0, 1705312200.0],
        "src_ip": ["192.168.1.100", "192.168.1.101"],
        "dst_ip": [None, None],
        "confidence": [0.75, 0.65],
        "metadata": [
            '{"unique_destinations": 50, "connection_count": 100}',
            '{"domain": "example.com", "query_count": 15}',
        ],
    }
    return pd.DataFrame(data)


@pytest.fixture
def detector_config():
    """Sample detector configuration."""
    return {
        "recon_scanning": {
            "enabled": True,
            "time_window_seconds": 300,
            "fan_out_threshold": 50,
            "burst_threshold": 100,
            "failed_connection_ratio": 0.5,
        },
        "dns_beaconing": {
            "enabled": True,
            "time_window_seconds": 600,
            "repeated_query_threshold": 10,
            "periodicity_window_seconds": 3600,
            "nxdomain_ratio_threshold": 0.3,
            "min_unique_domains": 3,
        },
    }


@pytest.fixture
def case_config():
    """Sample case assembly configuration."""
    return {
        "time_window_seconds": 1800,
        "min_evidence_rows": 5,
        "confidence_threshold": 0.6,
        "max_evidence_rows_per_case": 50,
    }
