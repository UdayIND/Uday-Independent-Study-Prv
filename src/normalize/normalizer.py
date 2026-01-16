"""Event normalizer for converting Zeek and Suricata events to unified schema."""

import json
import logging
from datetime import datetime
from typing import Any, Optional

import pandas as pd

logger = logging.getLogger(__name__)


class EventNormalizer:
    """Normalizes events from multiple sources into a unified schema."""

    # Target schema fields
    SCHEMA_FIELDS = [
        "ts",
        "sensor",
        "event_type",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "proto",
        "uid",
        "flow_id",
        "severity",
        "signature",
        "metadata",
        "case_id",
    ]

    def normalize(self, zeek_events: list[dict], suricata_events: list[dict]) -> pd.DataFrame:
        """Normalize events from Zeek and Suricata into unified DataFrame.

        Args:
            zeek_events: List of Zeek event dictionaries
            suricata_events: List of Suricata event dictionaries

        Returns:
            DataFrame with normalized events
        """
        normalized_rows = []

        # Normalize Zeek events
        for event in zeek_events:
            normalized = self._normalize_zeek_event(event)
            if normalized:
                normalized_rows.append(normalized)

        # Normalize Suricata events
        for event in suricata_events:
            normalized = self._normalize_suricata_event(event)
            if normalized:
                normalized_rows.append(normalized)

        # Create DataFrame
        df = pd.DataFrame(normalized_rows)

        # Ensure all schema fields are present
        for field in self.SCHEMA_FIELDS:
            if field not in df.columns:
                df[field] = None

        # Sort by timestamp
        if "ts" in df.columns and len(df) > 0:
            df = df.sort_values("ts")

        logger.info(f"Normalized {len(df)} events")
        return df

    def _normalize_zeek_event(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Normalize a single Zeek event.

        Args:
            event: Raw Zeek event dictionary

        Returns:
            Normalized event dictionary or None if invalid
        """
        try:
            normalized = {
                "ts": self._parse_timestamp(event.get("ts")),
                "sensor": event.get("sensor", "zeek"),
                "event_type": event.get("event_type", "unknown"),
                "src_ip": event.get("id.orig_h"),
                "dst_ip": event.get("id.resp_h"),
                "src_port": self._safe_int(event.get("id.orig_p")),
                "dst_port": self._safe_int(event.get("id.resp_p")),
                "proto": event.get("proto", "").lower(),
                "uid": event.get("uid"),
                "flow_id": None,  # Zeek uses uid, not flow_id
                "severity": None,  # Zeek doesn't have severity in conn/dns logs
                "signature": None,
                "metadata": json.dumps(
                    {k: v for k, v in event.items() if k not in self.SCHEMA_FIELDS}
                ),
                "case_id": None,  # Will be assigned during case assembly
            }
            return normalized
        except Exception as e:
            logger.warning(f"Failed to normalize Zeek event: {e}")
            return None

    def _normalize_suricata_event(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Normalize a single Suricata event.

        Args:
            event: Raw Suricata event dictionary

        Returns:
            Normalized event dictionary or None if invalid
        """
        try:
            # Suricata timestamp format
            ts = event.get("timestamp") or event.get("time")

            # Extract IPs and ports based on event type
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None

            if "src_ip" in event:
                src_ip = event["src_ip"]
                dst_ip = event.get("dest_ip")
                src_port = self._safe_int(event.get("src_port"))
                dst_port = self._safe_int(event.get("dest_port"))
            elif "source" in event:
                # Flow format
                src_ip = event["source"].get("ip")
                dst_ip = event.get("dest", {}).get("ip")
                src_port = self._safe_int(event["source"].get("port"))
                dst_port = self._safe_int(event.get("dest", {}).get("port"))

            normalized = {
                "ts": self._parse_timestamp(ts),
                "sensor": event.get("sensor", "suricata"),
                "event_type": event.get("event_type", "unknown"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": event.get("proto", "").lower(),
                "uid": None,  # Suricata doesn't use uid
                "flow_id": event.get("flow_id"),
                "severity": (
                    self._safe_int(event.get("alert", {}).get("severity"))
                    if "alert" in event
                    else None
                ),
                "signature": event.get("alert", {}).get("signature") if "alert" in event else None,
                "metadata": json.dumps(
                    {k: v for k, v in event.items() if k not in self.SCHEMA_FIELDS}
                ),
                "case_id": None,  # Will be assigned during case assembly
            }
            return normalized
        except Exception as e:
            logger.warning(f"Failed to normalize Suricata event: {e}")
            return None

    def _parse_timestamp(self, ts: Any) -> Optional[float]:
        """Parse timestamp to float (Unix epoch).

        Args:
            ts: Timestamp in various formats

        Returns:
            Unix timestamp as float or None
        """
        if ts is None:
            return None

        try:
            # If already a number
            if isinstance(ts, (int, float)):
                return float(ts)

            # If string, try parsing
            if isinstance(ts, str):
                # Try ISO format
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    return dt.timestamp()
                except ValueError:
                    pass

                # Try float conversion
                try:
                    return float(ts)
                except ValueError:
                    pass

            return None
        except Exception:
            return None

    def _safe_int(self, value: Any) -> Optional[int]:
        """Safely convert value to int.

        Args:
            value: Value to convert

        Returns:
            Integer or None
        """
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
