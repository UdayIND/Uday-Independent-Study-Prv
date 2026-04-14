"""Evidence agent for retrieving and scoring supporting rows from normalized events.

Implements relevance scoring based on:
- Temporal proximity to detection timestamp
- IP match quality (exact src > dst > subnet)
- Sensor diversity (multi-sensor evidence scores higher)
- Event type relevance (conn for recon, dns for beaconing)
"""

import logging
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class EvidenceAgent:
    """Retrieves and scores supporting evidence rows for cases."""

    def __init__(self, normalized_df: pd.DataFrame, config: dict[str, Any]):
        """Initialize evidence agent.

        Args:
            normalized_df: Normalized events DataFrame
            config: Case assembly configuration
        """
        self.normalized_df = normalized_df
        self.config = config
        self.max_rows = config.get("max_evidence_rows_per_case", 50)

    def retrieve_evidence(self, case: dict[str, Any], expand: bool = False) -> list[dict[str, Any]]:
        """Retrieve and score supporting evidence rows for a case.

        Args:
            case: Case dictionary
            expand: If True, expand search criteria

        Returns:
            List of evidence row dictionaries with relevance_score field
        """
        if len(self.normalized_df) == 0:
            return []

        # Build filter criteria
        filters = []

        # Filter by source IP
        if case.get("src_ip"):
            filters.append(self.normalized_df["src_ip"] == case["src_ip"])

        # Filter by destination IPs (skip if list is empty)
        if case.get("dst_ip") and isinstance(case["dst_ip"], list) and len(case["dst_ip"]) > 0:
            filters.append(self.normalized_df["dst_ip"].isin(case["dst_ip"]))

        # Filter by domain (for DNS cases)
        if case.get("domain") and len(case["domain"]) > 0:
            # Search in metadata for domain matches
            domain_filter = self.normalized_df["metadata"].str.contains(
                "|".join(case["domain"]), case=False, na=False
            )
            filters.append(domain_filter)

        # Filter by time window
        if case.get("ts_start") and case.get("ts_end"):
            ts_start = case["ts_start"]
            ts_end = case["ts_end"]

            # When ts_start == ts_end (single detection), use detection metadata
            # time_window or a default 300s window to capture related events
            if ts_start == ts_end:
                meta = case.get("metadata", {})
                if isinstance(meta, dict):
                    window = meta.get("time_window_seconds", 300)
                else:
                    window = 300
                ts_start = ts_start - window
                ts_end = ts_end + window

            # Expand time window further if requested
            if expand:
                time_expansion = max((ts_end - ts_start) * 0.5, 60)
                ts_start = ts_start - time_expansion
                ts_end = ts_end + time_expansion

            filters.append(self.normalized_df["ts"] >= ts_start)
            filters.append(self.normalized_df["ts"] <= ts_end)

        # Filter by detection type if applicable - but include both sensors
        # Don't filter by event_type to allow cross-sensor evidence
        if case.get("detection_type") and not expand:
            if case["detection_type"] == "dns_beaconing":
                filters.append(self.normalized_df["event_type"] == "dns")
            elif case["detection_type"] == "recon_scanning":
                filters.append(self.normalized_df["event_type"].isin(["conn", "flow"]))

        # Apply filters
        if filters:
            filtered_df = self.normalized_df[pd.concat(filters, axis=1).all(axis=1)].copy()
        else:
            filtered_df = self.normalized_df.copy()

        if len(filtered_df) == 0:
            return []

        # Calculate relevance scores
        filtered_df = self._score_evidence(filtered_df, case)

        # Sort by relevance score (descending), then timestamp
        filtered_df = filtered_df.sort_values(["relevance_score", "ts"], ascending=[False, True])

        # Limit rows
        if len(filtered_df) > self.max_rows:
            filtered_df = filtered_df.head(self.max_rows)

        evidence = filtered_df.to_dict("records")

        # Add mean relevance score to case metadata
        if evidence:
            mean_score = np.mean([e.get("relevance_score", 0) for e in evidence])
            case["mean_relevance_score"] = round(float(mean_score), 4)

        logger.info(
            f"Evidence agent retrieved {len(evidence)} rows for case {case.get('case_id')} "
            f"(mean_relevance={case.get('mean_relevance_score', 0):.3f})"
        )
        return evidence

    def _score_evidence(self, df: pd.DataFrame, case: dict[str, Any]) -> pd.DataFrame:
        """Calculate relevance scores for evidence rows.

        Scoring factors:
        1. Temporal proximity (0-1): closer to detection time = higher
        2. IP match quality (0-1): exact src_ip match = 1.0, dst_ip = 0.7
        3. Sensor diversity bonus (0-0.2): bonus for matching evidence from alternate sensor
        4. Event type relevance (0-1): matching event type for detection type

        Args:
            df: Filtered evidence DataFrame
            case: Case dictionary

        Returns:
            DataFrame with relevance_score column added
        """
        scores = pd.Series(0.0, index=df.index)

        # Factor 1: Temporal proximity (weight: 0.35)
        detection_ts = case.get("ts_start", case.get("ts", 0))
        if detection_ts and "ts" in df.columns:
            ts_numeric = pd.to_numeric(df["ts"], errors="coerce")
            time_diffs = (ts_numeric - detection_ts).abs()
            max_diff = time_diffs.max()
            if max_diff > 0:
                temporal_score = 1.0 - (time_diffs / max_diff)
            else:
                temporal_score = pd.Series(1.0, index=df.index)
            scores += temporal_score.fillna(0) * 0.35

        # Factor 2: IP match quality (weight: 0.30)
        ip_score = pd.Series(0.0, index=df.index)
        if case.get("src_ip") and "src_ip" in df.columns:
            ip_score = ip_score.where(df["src_ip"] != case["src_ip"], 1.0)
        if case.get("dst_ip") and "dst_ip" in df.columns:
            dst_ips = case["dst_ip"] if isinstance(case["dst_ip"], list) else [case["dst_ip"]]
            dst_match = df["dst_ip"].isin(dst_ips)
            ip_score = ip_score.where(~dst_match | (ip_score >= 0.7), 0.7)
        scores += ip_score * 0.30

        # Factor 3: Sensor diversity (weight: 0.15)
        if "sensor" in df.columns:
            sensors_present = df["sensor"].unique()
            if len(sensors_present) > 1:
                # Bonus for minority sensor (encourages cross-sensor evidence)
                sensor_counts = df["sensor"].value_counts()
                minority_sensor = sensor_counts.idxmin()
                diversity_score = pd.Series(0.0, index=df.index)
                diversity_score = diversity_score.where(df["sensor"] != minority_sensor, 1.0)
                scores += diversity_score * 0.15
            else:
                scores += 0.05  # Small base score for single-sensor

        # Factor 4: Event type relevance (weight: 0.20)
        detection_type = case.get("detection_type", "")
        if "event_type" in df.columns:
            relevance_map = {
                "recon_scanning": {"conn": 1.0, "flow": 0.9, "dns": 0.3},
                "dns_beaconing": {"dns": 1.0, "conn": 0.3, "flow": 0.3},
            }
            type_scores = relevance_map.get(detection_type, {})
            event_relevance = df["event_type"].map(type_scores).fillna(0.2)
            scores += event_relevance * 0.20

        df["relevance_score"] = scores.round(4)
        return df
