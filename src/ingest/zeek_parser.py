"""Parser for Zeek log files."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ZeekParser:
    """Parser for Zeek JSON log files."""

    def __init__(self, log_dir: Path):
        """Initialize parser with Zeek log directory.

        Args:
            log_dir: Path to directory containing Zeek log files
        """
        self.log_dir = Path(log_dir)

    def parse_conn_log(self) -> list[dict[str, Any]]:
        """Parse conn.log file.

        Returns:
            List of connection events as dictionaries
        """
        conn_log = self.log_dir / "conn.log"
        if not conn_log.exists():
            logger.warning(f"conn.log not found at {conn_log}")
            return []

        events = []
        try:
            with open(conn_log) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        event = json.loads(line)
                        event["event_type"] = "conn"
                        event["sensor"] = "zeek"
                        events.append(event)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse line in conn.log: {e}")
                        continue
        except Exception as e:
            logger.error(f"Error reading conn.log: {e}")

        logger.info(f"Parsed {len(events)} connection events from conn.log")
        return events

    def parse_dns_log(self) -> list[dict[str, Any]]:
        """Parse dns.log file.

        Returns:
            List of DNS events as dictionaries
        """
        dns_log = self.log_dir / "dns.log"
        if not dns_log.exists():
            logger.warning(f"dns.log not found at {dns_log}")
            return []

        events = []
        try:
            with open(dns_log) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        event = json.loads(line)
                        event["event_type"] = "dns"
                        event["sensor"] = "zeek"
                        events.append(event)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse line in dns.log: {e}")
                        continue
        except Exception as e:
            logger.error(f"Error reading dns.log: {e}")

        logger.info(f"Parsed {len(events)} DNS events from dns.log")
        return events

    def parse_all(self) -> list[dict[str, Any]]:
        """Parse all available Zeek log files.

        Returns:
            Combined list of all parsed events
        """
        events = []
        events.extend(self.parse_conn_log())
        events.extend(self.parse_dns_log())
        return events
