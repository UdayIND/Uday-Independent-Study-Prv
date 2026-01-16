"""Evidence agent for retrieving supporting rows from normalized events."""

import logging
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


class EvidenceAgent:
    """Retrieves supporting evidence rows for cases."""

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
        """Retrieve supporting evidence rows for a case.

        Args:
            case: Case dictionary
            expand: If True, expand search criteria

        Returns:
            List of evidence row dictionaries
        """
        if len(self.normalized_df) == 0:
            return []

        # Build filter criteria
        filters = []

        # Filter by source IP
        if case.get("src_ip"):
            filters.append(self.normalized_df["src_ip"] == case["src_ip"])

        # Filter by destination IPs
        if case.get("dst_ip") and len(case["dst_ip"]) > 0:
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
            # Expand time window if requested
            if expand:
                time_expansion = (case["ts_end"] - case["ts_start"]) * 0.5
                ts_start = case["ts_start"] - time_expansion
                ts_end = case["ts_end"] + time_expansion
            else:
                ts_start = case["ts_start"]
                ts_end = case["ts_end"]

            filters.append(self.normalized_df["ts"] >= ts_start)
            filters.append(self.normalized_df["ts"] <= ts_end)

        # Filter by detection type if applicable
        if case.get("detection_type"):
            if case["detection_type"] == "dns_beaconing":
                filters.append(self.normalized_df["event_type"] == "dns")
            elif case["detection_type"] == "recon_scanning":
                filters.append(self.normalized_df["event_type"].isin(["conn", "flow"]))

        # Apply filters
        if filters:
            filtered_df = self.normalized_df[pd.concat(filters, axis=1).all(axis=1)]
        else:
            filtered_df = self.normalized_df

        # Sort by timestamp
        filtered_df = filtered_df.sort_values("ts")

        # Limit rows
        if len(filtered_df) > self.max_rows:
            filtered_df = filtered_df.head(self.max_rows)

        evidence = filtered_df.to_dict("records")

        logger.info(f"Evidence agent retrieved {len(evidence)} rows for case {case.get('case_id')}")
        return evidence
