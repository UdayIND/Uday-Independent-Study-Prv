"""Tests for Zeek parser."""

from src.ingest.zeek_parser import ZeekParser


def test_parse_conn_log(sample_zeek_conn_log, temp_dir):
    """Test parsing Zeek conn.log."""
    parser = ZeekParser(temp_dir)
    events = parser.parse_conn_log()

    assert len(events) == 2
    assert events[0]["event_type"] == "conn"
    assert events[0]["sensor"] == "zeek"
    assert events[0]["id.orig_h"] == "192.168.1.100"
    assert events[0]["id.resp_h"] == "10.0.0.1"


def test_parse_dns_log(sample_zeek_dns_log, temp_dir):
    """Test parsing Zeek dns.log."""
    parser = ZeekParser(temp_dir)
    events = parser.parse_dns_log()

    assert len(events) == 1
    assert events[0]["event_type"] == "dns"
    assert events[0]["sensor"] == "zeek"
    assert events[0]["query"] == "example.com"


def test_parse_all(sample_zeek_conn_log, sample_zeek_dns_log, temp_dir):
    """Test parsing all Zeek logs."""
    parser = ZeekParser(temp_dir)
    events = parser.parse_all()

    assert len(events) == 3  # 2 conn + 1 dns
    assert any(e["event_type"] == "conn" for e in events)
    assert any(e["event_type"] == "dns" for e in events)


def test_parse_missing_log(temp_dir):
    """Test parsing when log file doesn't exist."""
    parser = ZeekParser(temp_dir)
    events = parser.parse_conn_log()

    assert len(events) == 0
