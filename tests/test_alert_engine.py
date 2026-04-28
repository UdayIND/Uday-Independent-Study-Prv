"""Tests for the SENTINEL-RL Telemetry Plane — AlertEngine."""

import time
from unittest.mock import MagicMock, patch

from src.ingest.alert_engine import AlertEngine


class TestAlertEngine:
    """Test the sliding-window AlertEngine (Section IV-C)."""

    def test_initialization_defaults(self):
        """Paper parameters: W=10s, N=25."""
        engine = AlertEngine()
        assert engine.window_seconds == 10
        assert engine.threshold == 25
        assert engine.alerts_fired == 0

    def test_custom_parameters(self):
        """Engine should accept custom W and N."""
        engine = AlertEngine(window_seconds=5, threshold=10)
        assert engine.window_seconds == 5
        assert engine.threshold == 10

    def test_no_alert_below_threshold(self):
        """Events below threshold should NOT trigger an alert."""
        engine = AlertEngine(window_seconds=10, threshold=5)
        now = time.time()
        for i in range(4):
            result = engine.process_event("host_a", timestamp=now + i)
            assert result is False
        assert engine.alerts_fired == 0

    @patch("src.ingest.alert_engine.requests.post")
    def test_alert_fires_at_threshold(self, mock_post):
        """N events from the same host within W seconds should trigger an alert."""
        mock_post.return_value = MagicMock(status_code=200)
        engine = AlertEngine(window_seconds=10, threshold=5)
        now = time.time()

        results = []
        for i in range(5):
            results.append(engine.process_event("host_a", timestamp=now + i))

        assert results[-1] is True  # 5th event triggers alert
        assert engine.alerts_fired == 1
        mock_post.assert_called_once()

    @patch("src.ingest.alert_engine.requests.post")
    def test_window_eviction(self, mock_post):
        """Events outside the window should be evicted."""
        mock_post.return_value = MagicMock(status_code=200)
        engine = AlertEngine(window_seconds=5, threshold=3)

        # Events at t=0,1,2 — no alert (only 3 needed but spread ok)
        base = 1000.0
        engine.process_event("host_b", timestamp=base)
        engine.process_event("host_b", timestamp=base + 1)
        # t=10: old events should be evicted (outside 5s window)
        result = engine.process_event("host_b", timestamp=base + 10)
        assert result is False  # Only 1 event in the current window

    @patch("src.ingest.alert_engine.requests.post")
    def test_per_host_isolation(self, mock_post):
        """Different hosts should have independent windows."""
        mock_post.return_value = MagicMock(status_code=200)
        engine = AlertEngine(window_seconds=10, threshold=3)
        now = time.time()

        engine.process_event("host_a", timestamp=now)
        engine.process_event("host_a", timestamp=now + 1)
        engine.process_event("host_b", timestamp=now)
        engine.process_event("host_b", timestamp=now + 1)

        # host_a reaches threshold
        result_a = engine.process_event("host_a", timestamp=now + 2)
        assert result_a is True

        # host_b should NOT have triggered
        assert engine.alerts_fired == 1

    @patch("src.ingest.alert_engine.requests.post")
    def test_batch_processing(self, mock_post):
        """process_batch should return alerted hosts."""
        mock_post.return_value = MagicMock(status_code=200)
        engine = AlertEngine(window_seconds=10, threshold=3)
        now = time.time()

        events = [
            {"src_host": "host_c", "ts": now},
            {"src_host": "host_c", "ts": now + 1},
            {"src_host": "host_c", "ts": now + 2},  # triggers
        ]
        alerted = engine.process_batch(events)
        assert "host_c" in alerted

    @patch("src.ingest.alert_engine.requests.post")
    def test_window_reset_after_alert(self, mock_post):
        """After an alert, the host's window should be cleared to prevent alert-storming."""
        mock_post.return_value = MagicMock(status_code=200)
        engine = AlertEngine(window_seconds=10, threshold=3)
        now = time.time()

        # Trigger first alert
        for i in range(3):
            engine.process_event("host_d", timestamp=now + i)
        assert engine.alerts_fired == 1

        # One more event should NOT immediately re-trigger
        result = engine.process_event("host_d", timestamp=now + 4)
        assert result is False
        assert engine.alerts_fired == 1
