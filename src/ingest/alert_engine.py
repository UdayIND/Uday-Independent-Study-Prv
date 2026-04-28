"""
SENTINEL-RL AlertEngine — Sliding-Window Alert Trigger.

Section IV-C of the paper: The telemetry plane monitors the raw authentication
stream using a fast sliding-window heuristic. If a specific source host
initiates more than N=25 authentications within a narrow W=10s timeframe,
the engine immediately fires a webhook.

This module is extracted as a standalone component from the live ingestion
pipeline for independent testing and benchmarking (Section VI-B).
"""

import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class AlertEngine:
    """Sliding-window alert engine (Section IV-C, VI-B).

    Monitors authentication events per source host and fires a webhook
    when the event count in a W-second window exceeds threshold N.

    Paper parameters: W=10s, N=25.
    """

    def __init__(
        self,
        window_seconds: int = 10,
        threshold: int = 25,
        webhook_url: Optional[str] = None,
    ):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.webhook_url = webhook_url or "http://localhost:8000/trigger_investigation"
        self.window: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()
        self.alerts_fired = 0

        logger.info(
            f"AlertEngine initialized (W={window_seconds}s, N={threshold}, "
            f"webhook={self.webhook_url})"
        )

    def process_event(self, src_host: str, timestamp: Optional[float] = None) -> bool:
        """Process a single authentication event.

        Args:
            src_host: Source host identifier.
            timestamp: Event timestamp (defaults to current time).

        Returns:
            True if an alert was triggered.
        """
        now = timestamp or time.time()
        cutoff = now - self.window_seconds

        with self.lock:
            self.window[src_host].append(now)

            # Evict stale events
            while self.window[src_host] and self.window[src_host][0] < cutoff:
                self.window[src_host].popleft()

            # Check threshold
            if len(self.window[src_host]) >= self.threshold:
                count = len(self.window[src_host])
                self.window[src_host].clear()  # Reset to avoid alert-storming
                self.alerts_fired += 1
                self._fire_webhook(src_host, count, now)
                return True

        return False

    def process_batch(self, events: list[dict]) -> list[str]:
        """Process a batch of events and return alerted host IDs.

        Args:
            events: List of dicts with 'src_host' and optional 'ts' keys.

        Returns:
            List of source hosts that triggered alerts.
        """
        alerted = []
        for event in events:
            src_host = event.get("src_host", event.get("src_ip", ""))
            ts = event.get("ts", event.get("timestamp", None))
            if src_host and self.process_event(src_host, ts):
                alerted.append(src_host)
        return alerted

    def _fire_webhook(self, src_host: str, count: int, timestamp: float):
        """Fire a webhook to the orchestration layer.

        Args:
            src_host: Alerted host identifier.
            count: Number of events in the window.
            timestamp: Time of the alert trigger.
        """
        payload = {
            "node_id": src_host,
            "event_count": count,
            "time_window": self.window_seconds,
            "timestamp": datetime.utcfromtimestamp(timestamp).isoformat(),
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=2.0)
            if response.status_code == 200:
                logger.info(
                    f"ALERT: {src_host} exceeded threshold ({count} events in {self.window_seconds}s)"
                )
            else:
                logger.warning(f"Webhook rejected: status {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Webhook failed for {src_host}: {e}")
