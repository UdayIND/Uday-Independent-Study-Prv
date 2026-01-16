"""Triage agent for grouping detections into candidate cases."""

import logging
from datetime import timedelta
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


class TriageAgent:
    """Groups raw detections into candidate cases."""

    def __init__(self, config: dict[str, Any]):
        """Initialize triage agent.

        Args:
            config: Case assembly configuration
        """
        self.config = config
        self.time_window = timedelta(seconds=config.get("time_window_seconds", 1800))

    def group_detections(self, detections: pd.DataFrame) -> list[dict[str, Any]]:
        """Group detections into candidate cases.

        Args:
            detections: DataFrame of detections

        Returns:
            List of case dictionaries
        """
        if len(detections) == 0:
            return []

        cases = []

        # Convert timestamp to datetime
        detections = detections.copy()
        if pd.api.types.is_numeric_dtype(detections["ts"]):
            detections["ts_dt"] = pd.to_datetime(detections["ts"], unit="s", errors="coerce")
        else:
            detections["ts_dt"] = pd.to_datetime(detections["ts"], errors="coerce")

        detections = detections.dropna(subset=["ts_dt", "src_ip"])

        if len(detections) == 0:
            return []

        # Group by detection type, source IP, and time window
        detections["time_bucket"] = (detections["ts_dt"] // self.time_window).astype(int)

        grouped = detections.groupby(["detection_type", "src_ip", "time_bucket"])

        case_id = 1
        for (detection_type, src_ip, time_bucket), group in grouped:
            case = {
                "case_id": f"CASE_{case_id:04d}",
                "detection_type": detection_type,
                "src_ip": src_ip,
                "dst_ip": (
                    group["dst_ip"].dropna().unique().tolist() if "dst_ip" in group.columns else []
                ),
                "domain": None,  # Will be populated for DNS cases
                "ts_start": group["ts"].min(),
                "ts_end": group["ts"].max(),
                "detection_count": len(group),
                "detections": group.to_dict("records"),
            }

            # Extract domain for DNS beaconing cases
            if detection_type == "dns_beaconing":
                domains = []
                for det in group.to_dict("records"):
                    if "metadata" in det and det["metadata"]:
                        domain = det["metadata"].get("domain")
                        if domain:
                            domains.append(domain)
                case["domain"] = list(set(domains)) if domains else None

            cases.append(case)
            case_id += 1

        logger.info(f"Triage agent grouped {len(detections)} detections into {len(cases)} cases")
        return cases
