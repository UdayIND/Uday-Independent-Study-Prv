"""Tests for PCAP healthcheck script."""

import subprocess
import tempfile
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).parent.parent
HEALTHCHECK_SCRIPT = SCRIPT_DIR / "scripts" / "pcap_healthcheck.sh"
FIXTURES_DIR = SCRIPT_DIR / "tests" / "fixtures"


def test_pcap_healthcheck_accepts_valid_pcap():
    """Test that healthcheck accepts a valid minimal PCAP."""
    minimal_pcap = FIXTURES_DIR / "minimal.pcap"
    if not minimal_pcap.exists():
        pytest.skip("minimal.pcap fixture not found")

    result = subprocess.run(
        [str(HEALTHCHECK_SCRIPT), str(minimal_pcap), "1"],  # 1KB minimum
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Valid PCAP file" in result.stdout


def test_pcap_healthcheck_rejects_html():
    """Test that healthcheck rejects HTML files."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
        f.write("<!DOCTYPE html><html><head><title>Test</title></head></html>")
        html_file = f.name

    try:
        result = subprocess.run(
            [str(HEALTHCHECK_SCRIPT), html_file],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0
        assert "Invalid PCAP file" in result.stdout or "HTML" in result.stdout
    finally:
        Path(html_file).unlink()


def test_pcap_healthcheck_rejects_nonexistent_file():
    """Test that healthcheck rejects nonexistent files."""
    result = subprocess.run(
        [str(HEALTHCHECK_SCRIPT), "/nonexistent/file.pcap"],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "not found" in result.stdout


def test_pcap_healthcheck_warns_on_small_file():
    """Test that healthcheck warns on very small files."""
    minimal_pcap = FIXTURES_DIR / "minimal.pcap"
    if not minimal_pcap.exists():
        pytest.skip("minimal.pcap fixture not found")

    result = subprocess.run(
        [str(HEALTHCHECK_SCRIPT), str(minimal_pcap), "100"],  # 100KB minimum
        capture_output=True,
        text=True,
    )

    # Should warn but not fail for small files
    assert "Warning" in result.stdout or "very small" in result.stdout
