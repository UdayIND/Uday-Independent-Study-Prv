"""Tests for the SENTINEL-RL Data Plane — LANL Loader."""

from unittest.mock import MagicMock, mock_open, patch

from src.ingest.lanl_loader import load_lanl_auth, parse_auth_line


class TestLanlLoader:
    """Test the two-phase CREATE LANL ingestion (Section V-A, Listing 1)."""

    def test_parse_auth_line_valid(self):
        """A valid auth.txt line should produce a structured event dict."""
        line = "100,U1@DOM1,U2@DOM2,C1,C2,NTLM,LogOn,AuthMap,Success"
        result = parse_auth_line(line)
        assert result is not None
        assert result["ts"] == 100
        assert result["src_user"] == "U1@DOM1"
        assert result["dst_user"] == "U2@DOM2"
        assert result["src_host"] == "C1"
        assert result["dst_host"] == "C2"
        assert result["auth_type"] == "NTLM"
        assert result["logon_type"] == "LogOn"
        assert result["success"] == "Success"

    def test_parse_auth_line_malformed(self):
        """Malformed lines should be skipped (return None)."""
        result = parse_auth_line("too,few,fields")
        assert result is None

    def test_parse_auth_line_empty(self):
        """Empty lines should be skipped."""
        result = parse_auth_line("")
        assert result is None


class TestLanlLoaderIntegration:
    """Integration-level tests (mocked Neo4j)."""

    @patch("src.ingest.lanl_loader.GraphDatabase.driver")
    @patch("src.ingest.lanl_loader.Path.exists", return_value=True)
    def test_loader_initializes_with_driver(self, mock_exists, mock_driver_factory):
        """Loader should create a Neo4j driver and process lines."""
        mock_driver = MagicMock()
        mock_driver_factory.return_value = mock_driver

        mock_csv_data = "100,U1@DOM1,U2@DOM2,C1,C2,NTLM,LogOn,AuthMap,Success\n"
        with patch("builtins.open", mock_open(read_data=mock_csv_data)):
            edges = load_lanl_auth(
                auth_path="fake_path.txt",
                neo4j_uri="neo4j://fake:7687",
                neo4j_user="neo4j",
                neo4j_password="test",
                batch_size=5000,
            )

        mock_driver_factory.assert_called_once()
        assert edges == 1
