"""Tests for CriticAgent."""

from src.agents.critic_agent import CriticAgent


def test_check_evidence_references_with_valid_evidence(case_config):
    """Test that evidence references check passes with structured evidence."""
    critic = CriticAgent(case_config)
    case = {
        "case_id": "CASE_0001",
        "detection_type": "recon_scanning",
        "detection_count": 5,
        "evidence": [
            {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "ts": 1705312200.0},
            {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.2", "ts": 1705312201.0},
        ],
    }
    result = critic._check_evidence_references(case)
    assert result is True


def test_check_evidence_references_with_empty_evidence(case_config):
    """Test that evidence references check fails with no evidence."""
    critic = CriticAgent(case_config)
    case = {"case_id": "CASE_0001", "evidence": []}
    result = critic._check_evidence_references(case)
    assert result is False


def test_check_evidence_references_with_unstructured_evidence(case_config):
    """Test that evidence references check fails with non-dict evidence."""
    critic = CriticAgent(case_config)
    case = {"case_id": "CASE_0001", "evidence": ["not a dict", 123]}
    result = critic._check_evidence_references(case)
    assert result is False


def test_check_evidence_references_with_empty_dicts(case_config):
    """Test that evidence with empty dicts (no referenceable fields) fails."""
    critic = CriticAgent(case_config)
    case = {"case_id": "CASE_0001", "evidence": [{"foo": "bar"}, {"baz": 1}]}
    result = critic._check_evidence_references(case)
    assert result is False


def test_validate_case_with_sufficient_evidence(case_config):
    """Test full validation with sufficient structured evidence."""
    case_config["min_evidence_rows"] = 2
    case_config["confidence_threshold"] = 0.3
    critic = CriticAgent(case_config)
    case = {
        "case_id": "CASE_0001",
        "detection_type": "recon_scanning",
        "detection_count": 5,
        "evidence": [
            {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "ts": 1705312200.0,
             "event_type": "conn", "sensor": "zeek"},
            {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.2", "ts": 1705312201.0,
             "event_type": "conn", "sensor": "zeek"},
            {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.3", "ts": 1705312202.0,
             "event_type": "conn", "sensor": "zeek"},
        ],
    }
    validation = critic.validate_case(case)
    assert validation["is_valid"] is True
    assert validation["has_references"] is True
    assert validation["confidence"] > 0


def test_validate_case_without_report_content(case_config):
    """Test that validation works without report_content being set."""
    case_config["min_evidence_rows"] = 1
    case_config["confidence_threshold"] = 0.1
    critic = CriticAgent(case_config)
    case = {
        "case_id": "CASE_0001",
        "detection_type": "dns_beaconing",
        "detection_count": 3,
        "evidence": [
            {"src_ip": "192.168.1.1", "ts": 1705312200.0, "sensor": "zeek"},
        ],
    }
    # No report_content key - should still pass
    assert "report_content" not in case
    validation = critic.validate_case(case)
    assert validation["has_references"] is True


def test_five_factor_confidence_scores(case_config):
    """Test that 5-factor confidence model returns all factor scores."""
    case_config["min_evidence_rows"] = 2
    case_config["confidence_threshold"] = 0.1
    critic = CriticAgent(case_config)
    case = {
        "case_id": "CASE_0001",
        "detection_type": "recon_scanning",
        "detection_count": 3,
        "detection_confidence": 0.8,
        "ts_start": 1705312200.0,
        "evidence": [
            {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "ts": 1705312200.0,
             "event_type": "conn", "sensor": "zeek"},
            {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.2", "ts": 1705312201.0,
             "event_type": "conn", "sensor": "suricata"},
        ],
    }
    validation = critic.validate_case(case)

    assert "factor_scores" in validation
    factors = validation["factor_scores"]
    assert "detection_strength" in factors
    assert "evidence_volume" in factors
    assert "sensor_diversity" in factors
    assert "temporal_concentration" in factors
    assert "cross_case_correlation" in factors


def test_sensor_diversity_boosts_confidence(case_config):
    """Test that multi-sensor evidence produces higher sensor_diversity score."""
    case_config["min_evidence_rows"] = 1
    case_config["confidence_threshold"] = 0.0
    critic = CriticAgent(case_config)

    # Single sensor
    case_single = {
        "case_id": "CASE_SINGLE",
        "detection_type": "recon_scanning",
        "detection_count": 1,
        "evidence": [
            {"src_ip": "192.168.1.1", "ts": 1705312200.0, "sensor": "zeek"},
            {"src_ip": "192.168.1.1", "ts": 1705312201.0, "sensor": "zeek"},
        ],
    }
    val_single = critic.validate_case(case_single)

    # Multi sensor
    case_multi = {
        "case_id": "CASE_MULTI",
        "detection_type": "recon_scanning",
        "detection_count": 1,
        "evidence": [
            {"src_ip": "192.168.1.1", "ts": 1705312200.0, "sensor": "zeek"},
            {"src_ip": "192.168.1.1", "ts": 1705312201.0, "sensor": "suricata"},
        ],
    }
    val_multi = critic.validate_case(case_multi)

    assert val_multi["factor_scores"]["sensor_diversity"] > val_single["factor_scores"]["sensor_diversity"]


def test_cross_case_correlation(case_config):
    """Test that cross-case correlation boosts confidence."""
    case_config["min_evidence_rows"] = 1
    case_config["confidence_threshold"] = 0.0
    critic = CriticAgent(case_config)

    all_cases = [
        {"case_id": "CASE_0001", "src_ip": "192.168.1.1"},
        {"case_id": "CASE_0002", "src_ip": "192.168.1.1"},
        {"case_id": "CASE_0003", "src_ip": "192.168.1.1"},
    ]

    case = {
        "case_id": "CASE_0001",
        "src_ip": "192.168.1.1",
        "detection_type": "recon_scanning",
        "detection_count": 1,
        "evidence": [
            {"src_ip": "192.168.1.1", "ts": 1705312200.0, "sensor": "zeek"},
        ],
    }
    val = critic.validate_case(case, all_cases=all_cases)

    assert val["factor_scores"]["cross_case_correlation"] > 0
