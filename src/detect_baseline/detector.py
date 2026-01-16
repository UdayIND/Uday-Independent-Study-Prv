"""Baseline detectors for recon/scanning and DNS beaconing."""

import logging
from datetime import timedelta
from typing import Any, Optional

import pandas as pd

logger = logging.getLogger(__name__)


class BaselineDetector:
    """Baseline threat detection algorithms."""

    def __init__(self, config: dict[str, Any]):
        """Initialize detector with configuration.

        Args:
            config: Detector configuration dictionary
        """
        self.config = config
        self.recon_config = config.get("recon_scanning", {})
        self.dns_config = config.get("dns_beaconing", {})

    def detect(self, df: pd.DataFrame) -> pd.DataFrame:
        """Run all baseline detectors.

        Args:
            df: Normalized events DataFrame

        Returns:
            DataFrame with detections
        """
        detections = []

        if self.recon_config.get("enabled", True):
            recon_detections = self._detect_recon_scanning(df)
            detections.extend(recon_detections)

        if self.dns_config.get("enabled", True):
            dns_detections = self._detect_dns_beaconing(df)
            detections.extend(dns_detections)

        if detections:
            return pd.DataFrame(detections)
        else:
            return pd.DataFrame(
                columns=["detection_type", "ts", "src_ip", "dst_ip", "confidence", "metadata"]
            )

    def _detect_recon_scanning(self, df: pd.DataFrame) -> list[dict[str, Any]]:
        """Detect reconnaissance and scanning activity.

        Args:
            df: Normalized events DataFrame

        Returns:
            List of detection dictionaries
        """
        detections = []

        if len(df) == 0:
            return detections

        # Filter to connection events
        conn_df = df[df["event_type"].isin(["conn", "flow"])].copy()
        if len(conn_df) == 0:
            return detections

        # Convert timestamp to datetime if needed
        if pd.api.types.is_numeric_dtype(conn_df["ts"]):
            conn_df["ts_dt"] = pd.to_datetime(conn_df["ts"], unit="s", errors="coerce")
        else:
            conn_df["ts_dt"] = pd.to_datetime(conn_df["ts"], errors="coerce")

        conn_df = conn_df.dropna(subset=["ts_dt", "src_ip"])

        if len(conn_df) == 0:
            return detections

        time_window = timedelta(seconds=self.recon_config.get("time_window_seconds", 300))
        fan_out_threshold = self.recon_config.get("fan_out_threshold", 50)

        # Group by source IP and time window
        # Convert time_window to seconds for bucket calculation
        time_window_seconds = int(time_window.total_seconds())
        conn_df["time_bucket"] = (
            conn_df["ts_dt"].astype("int64") // 1e9 // time_window_seconds
        ).astype(int)

        # Calculate fan-out per source IP per time bucket
        fan_out = (
            conn_df.groupby(["src_ip", "time_bucket"])
            .agg(
                {
                    "dst_ip": "nunique",
                    "ts": ["min", "max", "count"],
                }
            )
            .reset_index()
        )

        fan_out.columns = ["src_ip", "time_bucket", "unique_dsts", "ts_min", "ts_max", "conn_count"]

        # Detect high fan-out
        high_fanout = fan_out[fan_out["unique_dsts"] >= fan_out_threshold]

        for _, row in high_fanout.iterrows():
            detections.append(
                {
                    "detection_type": "recon_scanning",
                    "ts": row["ts_min"],
                    "src_ip": row["src_ip"],
                    "dst_ip": None,  # Multiple destinations
                    "confidence": min(0.9, row["unique_dsts"] / fan_out_threshold * 0.5),
                    "metadata": {
                        "unique_destinations": int(row["unique_dsts"]),
                        "connection_count": int(row["conn_count"]),
                        "time_window_seconds": time_window.total_seconds(),
                    },
                }
            )

        logger.info(f"Detected {len(detections)} recon/scanning events")
        return detections

    def _detect_dns_beaconing(self, df: pd.DataFrame) -> list[dict[str, Any]]:
        """Detect DNS beaconing activity.

        Args:
            df: Normalized events DataFrame

        Returns:
            List of detection dictionaries
        """
        detections = []

        if len(df) == 0:
            return detections

        # Filter to DNS events
        dns_df = df[df["event_type"] == "dns"].copy()
        if len(dns_df) == 0:
            return detections

        # Extract domain from metadata
        dns_df["domain"] = dns_df["metadata"].apply(self._extract_domain_from_metadata)
        dns_df = dns_df.dropna(subset=["domain", "src_ip"])

        if len(dns_df) == 0:
            return detections

        # Convert timestamp
        if pd.api.types.is_numeric_dtype(dns_df["ts"]):
            dns_df["ts_dt"] = pd.to_datetime(dns_df["ts"], unit="s", errors="coerce")
        else:
            dns_df["ts_dt"] = pd.to_datetime(dns_df["ts"], errors="coerce")

        dns_df = dns_df.dropna(subset=["ts_dt"])

        if len(dns_df) == 0:
            return detections

        repeated_threshold = self.dns_config.get("repeated_query_threshold", 10)

        # Group by source IP and domain
        domain_counts = (
            dns_df.groupby(["src_ip", "domain"])
            .agg(
                {
                    "ts": ["min", "max", "count"],
                }
            )
            .reset_index()
        )

        domain_counts.columns = ["src_ip", "domain", "ts_min", "ts_max", "query_count"]

        # Convert timestamps back to numeric for duration calculation
        if len(domain_counts) > 0:
            domain_counts["ts_min"] = pd.to_numeric(domain_counts["ts_min"], errors="coerce")
            domain_counts["ts_max"] = pd.to_numeric(domain_counts["ts_max"], errors="coerce")

        # Detect repeated queries
        repeated = domain_counts[domain_counts["query_count"] >= repeated_threshold]

        for _, row in repeated.iterrows():
            # Calculate periodicity proxy (queries per hour)
            time_span = row["ts_max"] - row["ts_min"]
            if time_span > 0:
                queries_per_hour = row["query_count"] / (time_span / 3600)
            else:
                queries_per_hour = float("inf")

            detections.append(
                {
                    "detection_type": "dns_beaconing",
                    "ts": row["ts_min"],
                    "src_ip": row["src_ip"],
                    "dst_ip": None,  # DNS queries don't have direct dst_ip
                    "confidence": min(0.9, row["query_count"] / repeated_threshold * 0.5),
                    "metadata": {
                        "domain": row["domain"],
                        "query_count": int(row["query_count"]),
                        "queries_per_hour": queries_per_hour,
                    },
                }
            )

        logger.info(f"Detected {len(detections)} DNS beaconing events")
        return detections

    def _extract_domain_from_metadata(self, metadata_str: str) -> Optional[str]:
        """Extract domain name from metadata JSON string.

        Args:
            metadata_str: JSON string containing metadata

        Returns:
            Domain name or None
        """
        try:
            import json

            metadata = json.loads(metadata_str)
            # Try common field names
            for field in ["query", "domain", "qname", "rrname"]:
                if field in metadata:
                    return metadata[field]
            return None
        except Exception:
            return None
