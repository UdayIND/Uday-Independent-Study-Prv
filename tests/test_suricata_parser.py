"""Tests for Suricata parser."""

from src.ingest.suricata_parser import SuricataParser


def test_parse_eve_json(sample_suricata_eve_json, temp_dir):
    """Test parsing Suricata eve.json."""
    parser = SuricataParser(temp_dir)
    events = parser.parse_eve_json()

    assert len(events) == 2
    assert events[0]["sensor"] == "suricata"
    assert events[0]["event_type"] == "flow"
    assert events[1]["event_type"] == "alert"


def test_parse_all(sample_suricata_eve_json, temp_dir):
    """Test parsing all Suricata logs."""
    parser = SuricataParser(temp_dir)
    events = parser.parse_all()

    assert len(events) == 2


def test_parse_missing_log(temp_dir):
    """Test parsing when log file doesn't exist."""
    parser = SuricataParser(temp_dir)
    events = parser.parse_eve_json()

    assert len(events) == 0
