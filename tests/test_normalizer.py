"""Tests for event normalizer."""

from src.normalize.normalizer import EventNormalizer


def test_normalize_zeek_events(sample_zeek_conn_log, sample_zeek_dns_log, temp_dir):
    """Test normalizing Zeek events."""
    from src.ingest.zeek_parser import ZeekParser

    parser = ZeekParser(temp_dir)
    zeek_events = parser.parse_all()

    normalizer = EventNormalizer()
    df = normalizer.normalize(zeek_events, [])

    assert len(df) == 3
    assert "ts" in df.columns
    assert "sensor" in df.columns
    assert "src_ip" in df.columns
    assert all(df["sensor"] == "zeek")


def test_normalize_suricata_events(sample_suricata_eve_json, temp_dir):
    """Test normalizing Suricata events."""
    from src.ingest.suricata_parser import SuricataParser

    parser = SuricataParser(temp_dir)
    suricata_events = parser.parse_all()

    normalizer = EventNormalizer()
    df = normalizer.normalize([], suricata_events)

    assert len(df) == 2
    assert all(df["sensor"] == "suricata")


def test_normalize_combined(
    sample_zeek_conn_log, sample_zeek_dns_log, sample_suricata_eve_json, temp_dir
):
    """Test normalizing combined Zeek and Suricata events."""
    from src.ingest.suricata_parser import SuricataParser
    from src.ingest.zeek_parser import ZeekParser

    zeek_parser = ZeekParser(temp_dir)
    suricata_parser = SuricataParser(temp_dir)

    zeek_events = zeek_parser.parse_all()
    suricata_events = suricata_parser.parse_all()

    normalizer = EventNormalizer()
    df = normalizer.normalize(zeek_events, suricata_events)

    assert len(df) == 5  # 3 zeek + 2 suricata
    assert len(df[df["sensor"] == "zeek"]) == 3
    assert len(df[df["sensor"] == "suricata"]) == 2


def test_normalize_empty():
    """Test normalizing empty event lists."""
    normalizer = EventNormalizer()
    df = normalizer.normalize([], [])

    assert len(df) == 0
    # Check that schema fields are present
    for field in EventNormalizer.SCHEMA_FIELDS:
        assert field in df.columns
