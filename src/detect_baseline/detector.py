"""Baseline detectors for recon/scanning and DNS beaconing.

Implements multi-signal detection with configurable thresholds:
- Recon scanning: fan-out, burst rate, failed connection ratio
- DNS beaconing: repeated queries, periodicity (CV), NXDOMAIN ratio, domain diversity
"""

import logging
from datetime import timedelta
from typing import Any, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class BaselineDetector:
    """Baseline threat detection algorithms with multi-signal scoring."""

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
        """Detect reconnaissance and scanning activity using multi-signal analysis.

        Signals:
        1. Fan-out: unique destination IPs exceeding threshold
        2. Burst rate: connections per second exceeding burst_threshold
        3. Failed connection ratio: proportion of failed/rejected connections

        Confidence is a weighted combination of all active signals.

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

        # Load all config parameters
        time_window = timedelta(seconds=self.recon_config.get("time_window_seconds", 300))
        fan_out_threshold = self.recon_config.get("fan_out_threshold", 50)
        burst_threshold = self.recon_config.get("burst_threshold", 100)
        failed_connection_ratio = self.recon_config.get("failed_connection_ratio", 0.5)

        # Group by source IP and time window
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

        # Detect high fan-out (primary signal)
        high_fanout = fan_out[fan_out["unique_dsts"] >= fan_out_threshold]

        for _, row in high_fanout.iterrows():
            src_ip = row["src_ip"]
            bucket = row["time_bucket"]

            # Get connection-level data for this source+bucket
            bucket_conns = conn_df[
                (conn_df["src_ip"] == src_ip) & (conn_df["time_bucket"] == bucket)
            ]

            # Signal 1: Fan-out score (0-1)
            fan_out_score = min(1.0, row["unique_dsts"] / (fan_out_threshold * 2))

            # Signal 2: Burst detection
            # Count max connections in any 1-second window
            burst_detected = False
            max_conns_per_sec = 0
            if len(bucket_conns) > 1:
                epoch_secs = bucket_conns["ts_dt"].astype("int64") // 10**9
                sec_counts = epoch_secs.value_counts()
                max_conns_per_sec = int(sec_counts.max()) if len(sec_counts) > 0 else 0
                burst_detected = max_conns_per_sec >= burst_threshold
            burst_score = (
                min(1.0, max_conns_per_sec / burst_threshold) if burst_threshold > 0 else 0.0
            )

            # Signal 3: Failed connection ratio
            # Check conn_state field in metadata for failed indicators
            failed_count = 0
            total_count = len(bucket_conns)
            if "conn_state" in bucket_conns.columns:
                failed_states = {"S0", "REJ", "RSTO", "RSTOS0", "SH", "SHR", "OTH"}
                failed_count = bucket_conns["conn_state"].isin(failed_states).sum()
            elif "metadata" in bucket_conns.columns:
                # Try extracting conn_state from metadata JSON
                for _, conn_row in bucket_conns.iterrows():
                    try:
                        import json

                        meta = json.loads(str(conn_row.get("metadata", "{}")))
                        if meta.get("conn_state") in {
                            "S0",
                            "REJ",
                            "RSTO",
                            "RSTOS0",
                            "SH",
                            "SHR",
                            "OTH",
                        }:
                            failed_count += 1
                    except Exception:
                        pass

            actual_failed_ratio = failed_count / total_count if total_count > 0 else 0.0
            high_failure = actual_failed_ratio >= failed_connection_ratio
            failed_conn_score = (
                min(1.0, actual_failed_ratio / failed_connection_ratio)
                if failed_connection_ratio > 0
                else 0.0
            )

            # Multi-signal confidence: weighted combination
            # Fan-out is the primary signal (weight 0.5), burst and failed are secondary (0.25 each)
            confidence = fan_out_score * 0.5 + burst_score * 0.25 + failed_conn_score * 0.25
            confidence = min(0.95, confidence)

            detections.append(
                {
                    "detection_type": "recon_scanning",
                    "ts": row["ts_min"],
                    "src_ip": src_ip,
                    "dst_ip": None,
                    "confidence": round(confidence, 4),
                    "metadata": {
                        "unique_destinations": int(row["unique_dsts"]),
                        "connection_count": int(row["conn_count"]),
                        "time_window_seconds": time_window.total_seconds(),
                        "burst_detected": burst_detected,
                        "max_conns_per_sec": max_conns_per_sec,
                        "failed_connection_ratio": round(actual_failed_ratio, 4),
                        "high_failure_rate": high_failure,
                        "signal_scores": {
                            "fan_out": round(fan_out_score, 4),
                            "burst": round(burst_score, 4),
                            "failed_conn": round(failed_conn_score, 4),
                        },
                    },
                }
            )

        logger.info(f"Detected {len(detections)} recon/scanning events")
        return detections

    def _detect_dns_beaconing(self, df: pd.DataFrame) -> list[dict[str, Any]]:
        """Detect DNS beaconing activity using multi-signal analysis.

        Signals:
        1. Repeated queries: same domain queried >= threshold times
        2. Periodicity: low coefficient of variation in inter-query intervals
        3. NXDOMAIN ratio: high ratio of failed DNS lookups
        4. Domain diversity: source querying many unique domains

        Confidence is a weighted combination of all active signals.

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

        # Extract domain and response code from metadata
        dns_df["domain"] = dns_df["metadata"].apply(self._extract_domain_from_metadata)
        dns_df["rcode"] = dns_df["metadata"].apply(self._extract_rcode_from_metadata)
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

        # Load all config parameters
        repeated_threshold = self.dns_config.get("repeated_query_threshold", 10)
        self.dns_config.get("periodicity_window_seconds", 3600)
        nxdomain_ratio_threshold = self.dns_config.get("nxdomain_ratio_threshold", 0.3)
        min_unique_domains = self.dns_config.get("min_unique_domains", 3)

        # Pre-compute per-source statistics for NXDOMAIN and domain diversity
        src_stats = {}
        for src_ip, src_group in dns_df.groupby("src_ip"):
            total_queries = len(src_group)
            nxdomain_count = (src_group["rcode"] == "NXDOMAIN").sum()
            nxdomain_ratio = nxdomain_count / total_queries if total_queries > 0 else 0.0
            unique_domains = src_group["domain"].nunique()
            src_stats[src_ip] = {
                "nxdomain_ratio": nxdomain_ratio,
                "nxdomain_count": int(nxdomain_count),
                "total_queries": int(total_queries),
                "unique_domain_count": int(unique_domains),
            }

        # Group by source IP and domain for repeated query detection
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

        # Signal 4 pre-filter: min_unique_domains
        # Only consider sources querying at least min_unique_domains distinct domains
        qualified_sources = {
            src_ip
            for src_ip, stats in src_stats.items()
            if stats["unique_domain_count"] >= min_unique_domains
        }

        # Detect repeated queries (primary signal)
        repeated = domain_counts[domain_counts["query_count"] >= repeated_threshold]

        for _, row in repeated.iterrows():
            src_ip = row["src_ip"]

            # Skip sources with too few unique domains
            if src_ip not in qualified_sources:
                continue

            # Signal 1: Repeated query score
            repeat_score = min(1.0, row["query_count"] / (repeated_threshold * 2))

            # Signal 2: Periodicity analysis (coefficient of variation of inter-query intervals)
            periodicity_cv = None
            periodicity_score = 0.0
            domain_queries = dns_df[
                (dns_df["src_ip"] == src_ip) & (dns_df["domain"] == row["domain"])
            ].sort_values("ts_dt")

            if len(domain_queries) >= 3:
                timestamps = domain_queries["ts_dt"].astype("int64") // 10**9
                intervals = np.diff(timestamps.values).astype(float)
                if len(intervals) > 0 and np.mean(intervals) > 0:
                    periodicity_cv = float(np.std(intervals) / np.mean(intervals))
                    # Low CV means high periodicity (beacon-like)
                    # CV < 0.5 is highly periodic, CV > 2.0 is random
                    periodicity_score = max(0.0, 1.0 - periodicity_cv / 2.0)

            # Signal 3: NXDOMAIN ratio score
            stats = src_stats.get(src_ip, {})
            nxdomain_ratio = stats.get("nxdomain_ratio", 0.0)
            high_nxdomain = nxdomain_ratio >= nxdomain_ratio_threshold
            nxdomain_score = (
                min(1.0, nxdomain_ratio / nxdomain_ratio_threshold)
                if nxdomain_ratio_threshold > 0
                else 0.0
            )

            # Signal 4: Domain diversity score
            unique_domains = stats.get("unique_domain_count", 0)
            domain_diversity_score = min(1.0, unique_domains / (min_unique_domains * 3))

            # Calculate periodicity proxy (queries per hour)
            time_span = row["ts_max"] - row["ts_min"]
            if time_span > 0:
                queries_per_hour = row["query_count"] / (time_span / 3600)
            else:
                queries_per_hour = float("inf")

            # Multi-signal confidence: weighted combination
            # Repeated queries (0.35), periodicity (0.30), NXDOMAIN (0.20), domain diversity (0.15)
            confidence = (
                repeat_score * 0.35
                + periodicity_score * 0.30
                + nxdomain_score * 0.20
                + domain_diversity_score * 0.15
            )
            confidence = min(0.95, confidence)

            detections.append(
                {
                    "detection_type": "dns_beaconing",
                    "ts": row["ts_min"],
                    "src_ip": src_ip,
                    "dst_ip": None,
                    "confidence": round(confidence, 4),
                    "metadata": {
                        "domain": row["domain"],
                        "query_count": int(row["query_count"]),
                        "queries_per_hour": queries_per_hour,
                        "periodicity_cv": periodicity_cv,
                        "nxdomain_ratio": round(nxdomain_ratio, 4),
                        "high_nxdomain": high_nxdomain,
                        "unique_domain_count": unique_domains,
                        "signal_scores": {
                            "repeated_query": round(repeat_score, 4),
                            "periodicity": round(periodicity_score, 4),
                            "nxdomain": round(nxdomain_score, 4),
                            "domain_diversity": round(domain_diversity_score, 4),
                        },
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

    def _extract_rcode_from_metadata(self, metadata_str: str) -> Optional[str]:
        """Extract DNS response code from metadata JSON string.

        Args:
            metadata_str: JSON string containing metadata

        Returns:
            Response code string (e.g., 'NOERROR', 'NXDOMAIN') or None
        """
        try:
            import json

            metadata = json.loads(metadata_str)
            for field in ["rcode", "rcode_name", "dns_rcode", "response_code"]:
                if field in metadata:
                    return str(metadata[field])
            return None
        except Exception:
            return None
