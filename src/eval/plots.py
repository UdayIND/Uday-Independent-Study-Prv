"""Generate matplotlib plots for evaluation metrics."""

import logging
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import pandas as pd

logger = logging.getLogger(__name__)


def plot_events_per_minute(normalized_df: pd.DataFrame, output_path: Path) -> None:
    """Plot events per minute over time.

    Args:
        normalized_df: Normalized events DataFrame
        output_path: Path to save PNG file
    """
    if normalized_df.empty or "ts" not in normalized_df.columns:
        logger.warning("Cannot plot events per minute: missing data or timestamp column")
        return

    ts_series = pd.to_datetime(normalized_df["ts"], errors="coerce", unit="s")
    ts_valid = ts_series.dropna()
    if ts_valid.empty:
        logger.warning("No valid timestamps for events per minute plot")
        return

    # Group by minute
    ts_valid.index = ts_valid
    events_per_minute = ts_valid.resample("1T").count()

    plt.figure(figsize=(10, 6))
    plt.plot(events_per_minute.index, events_per_minute.values, linewidth=2)
    plt.xlabel("Time")
    plt.ylabel("Events per Minute")
    plt.title("Events per Minute Over Time")
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_top_ips(normalized_df: pd.DataFrame, column: str, output_path: Path, title: str) -> None:
    """Plot top IPs by count.

    Args:
        normalized_df: Normalized events DataFrame
        column: Column name ('src_ip' or 'dst_ip')
        output_path: Path to save PNG file
        title: Plot title
    """
    if normalized_df.empty or column not in normalized_df.columns:
        logger.warning(f"Cannot plot top {column}: missing data or column")
        return

    top_ips = normalized_df[column].value_counts().head(10)
    if top_ips.empty:
        logger.warning(f"No data for top {column} plot")
        return

    plt.figure(figsize=(10, 6))
    plt.barh(range(len(top_ips)), top_ips.values)
    plt.yticks(range(len(top_ips)), top_ips.index)
    plt.xlabel("Event Count")
    plt.ylabel("IP Address")
    plt.title(title)
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_protocol_breakdown(normalized_df: pd.DataFrame, output_path: Path) -> None:
    """Plot protocol breakdown.

    Args:
        normalized_df: Normalized events DataFrame
        output_path: Path to save PNG file
    """
    if normalized_df.empty or "proto" not in normalized_df.columns:
        logger.warning("Cannot plot protocol breakdown: missing data or proto column")
        return

    proto_counts = normalized_df["proto"].value_counts()
    if proto_counts.empty:
        logger.warning("No protocol data for breakdown plot")
        return

    plt.figure(figsize=(10, 6))
    plt.bar(range(len(proto_counts)), proto_counts.values)
    plt.xticks(range(len(proto_counts)), proto_counts.index, rotation=45)
    plt.xlabel("Protocol")
    plt.ylabel("Event Count")
    plt.title("Protocol Breakdown")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_dns_top_domains(dns_stats: dict[str, Any], output_path: Path) -> None:
    """Plot top DNS domains.

    Args:
        dns_stats: DNS statistics dictionary
        output_path: Path to save PNG file
    """
    top_domains = dns_stats.get("top_domains", [])
    if not top_domains:
        logger.warning("No DNS domain data for plot")
        return

    domains = [d["domain"] for d in top_domains]
    counts = [d["count"] for d in top_domains]

    plt.figure(figsize=(10, 6))
    plt.barh(range(len(domains)), counts)
    plt.yticks(range(len(domains)), domains)
    plt.xlabel("Query Count")
    plt.ylabel("Domain")
    plt.title("Top DNS Domains")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_suricata_alerts_by_signature(suricata_stats: dict[str, Any], output_path: Path) -> None:
    """Plot Suricata alerts by signature (top 10).

    Args:
        suricata_stats: Suricata statistics dictionary
        output_path: Path to save PNG file
    """
    alerts = suricata_stats.get("alerts_by_signature", [])
    if not alerts:
        logger.warning("No Suricata alert data for plot")
        return

    signatures = [a["signature"] for a in alerts[:10]]
    counts = [a["count"] for a in alerts[:10]]

    plt.figure(figsize=(12, 6))
    plt.barh(range(len(signatures)), counts)
    plt.yticks(range(len(signatures)), signatures)
    plt.xlabel("Alert Count")
    plt.ylabel("Signature")
    plt.title("Top 10 Suricata Alerts by Signature")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_detections_over_time(detections: list[dict[str, Any]], output_path: Path) -> None:
    """Plot detections over time.

    Args:
        detections: List of detection dictionaries
        output_path: Path to save PNG file
    """
    if not detections:
        logger.warning("No detections for timeline plot")
        return

    detections_df = pd.DataFrame(detections)
    if "ts" not in detections_df.columns:
        logger.warning("Cannot plot detections over time: missing ts column")
        return

    ts_series = pd.to_datetime(detections_df["ts"], errors="coerce", unit="s")
    ts_valid = ts_series.dropna()
    if ts_valid.empty:
        logger.warning("No valid timestamps for detections timeline plot")
        return

    # Group by minute
    ts_valid.index = ts_valid
    detections_per_minute = ts_valid.resample("1T").count()

    plt.figure(figsize=(10, 6))
    plt.plot(detections_per_minute.index, detections_per_minute.values, marker="o", linewidth=2)
    plt.xlabel("Time")
    plt.ylabel("Detections per Minute")
    plt.title("Detections Over Time")
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_detections_by_type(detections: list[dict[str, Any]], output_path: Path) -> None:
    """Plot detections by type.

    Args:
        detections: List of detection dictionaries
        output_path: Path to save PNG file
    """
    if not detections:
        logger.warning("No detections for type breakdown plot")
        return

    detections_df = pd.DataFrame(detections)
    if "detection_type" not in detections_df.columns:
        logger.warning("Cannot plot detections by type: missing detection_type column")
        return

    type_counts = detections_df["detection_type"].value_counts()

    plt.figure(figsize=(10, 6))
    plt.bar(range(len(type_counts)), type_counts.values)
    plt.xticks(range(len(type_counts)), type_counts.index, rotation=45)
    plt.xlabel("Detection Type")
    plt.ylabel("Count")
    plt.title("Detections by Type")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_cases_by_confidence(cases: list[dict[str, Any]], output_path: Path) -> None:
    """Plot cases by confidence (histogram or bar buckets).

    Args:
        cases: List of case dictionaries
        output_path: Path to save PNG file
    """
    if not cases:
        logger.warning("No cases for confidence plot")
        return

    confidences = []
    for case in cases:
        validation = case.get("validation", {})
        confidence = validation.get("confidence", 0.5)
        confidences.append(confidence)

    if not confidences:
        logger.warning("No confidence scores for plot")
        return

    plt.figure(figsize=(10, 6))
    plt.hist(confidences, bins=10, edgecolor="black", alpha=0.7)
    plt.xlabel("Confidence Score")
    plt.ylabel("Number of Cases")
    plt.title("Cases by Confidence Score")
    plt.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
