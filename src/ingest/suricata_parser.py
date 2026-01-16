"""Parser for Suricata eve.json log file."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SuricataParser:
    """Parser for Suricata eve.json log file."""

    def __init__(self, log_dir: Path):
        """Initialize parser with Suricata log directory.

        Args:
            log_dir: Path to directory containing Suricata log files
        """
        self.log_dir = Path(log_dir)

    def parse_eve_json(self) -> list[dict[str, Any]]:
        """Parse eve.json file.

        Returns:
            List of Suricata events as dictionaries
        """
        eve_json = self.log_dir / "eve.json"
        if not eve_json.exists():
            logger.warning(f"eve.json not found at {eve_json}")
            return []

        events = []
        try:
            with open(eve_json) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        event["sensor"] = "suricata"
                        # Preserve event_type from Suricata (alert, flow, dns, http, etc.)
                        if "event_type" not in event:
                            event["event_type"] = event.get("event_type", "unknown")
                        events.append(event)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse line in eve.json: {e}")
                        continue
        except Exception as e:
            logger.error(f"Error reading eve.json: {e}")

        logger.info(f"Parsed {len(events)} events from eve.json")
        return events

    def parse_all(self) -> list[dict[str, Any]]:
        """Parse all available Suricata log files.

        Returns:
            List of all parsed events
        """
        return self.parse_eve_json()
