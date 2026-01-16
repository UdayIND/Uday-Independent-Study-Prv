"""Compute evaluation metrics from normalized events and detections."""

import logging
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


def compute_data_health_metrics(normalized_df: pd.DataFrame) -> dict[str, Any]:
    """Compute data health metrics from normalized events.

    Args:
        normalized_df: Normalized events DataFrame

    Returns:
        Dictionary of data health metrics
    """
    metrics = {}

    if normalized_df.empty:
        logger.warning("Normalized DataFrame is empty, returning empty metrics")
        return {
            "total_events": 0,
            "sensor_counts": {},
            "event_type_counts": {},
            "missing_value_rates": {},
            "timestamp_range": {},
            "event_rate_per_minute": 0.0,
            "top_src_ips": [],
            "top_dst_ips": [],
            "top_ports": [],
            "dns_stats": {},
            "suricata_stats": {},
        }

    # Basic counts
    metrics["total_events"] = len(normalized_df)

    # Sensor and event type counts
    if "sensor" in normalized_df.columns:
        metrics["sensor_counts"] = normalized_df["sensor"].value_counts().to_dict()
    else:
        metrics["sensor_counts"] = {}

    if "event_type" in normalized_df.columns:
        metrics["event_type_counts"] = normalized_df["event_type"].value_counts().to_dict()
    else:
        metrics["event_type_counts"] = {}

    # Missing value rates for key fields
    key_fields = ["ts", "src_ip", "dst_ip", "proto"]
    missing_rates = {}
    for field in key_fields:
        if field in normalized_df.columns:
            missing_rates[field] = normalized_df[field].isna().sum() / len(normalized_df)
        else:
            missing_rates[field] = 1.0
    metrics["missing_value_rates"] = missing_rates

    # Timestamp range and event rate
    if "ts" in normalized_df.columns and not normalized_df["ts"].isna().all():
        ts_series = pd.to_datetime(normalized_df["ts"], errors="coerce", unit="s")
        ts_valid = ts_series.dropna()
        if not ts_valid.empty:
            ts_min = ts_valid.min()
            ts_max = ts_valid.max()
            duration_minutes = (ts_max - ts_min).total_seconds() / 60.0
            if duration_minutes > 0:
                metrics["event_rate_per_minute"] = len(normalized_df) / duration_minutes
            else:
                metrics["event_rate_per_minute"] = 0.0
            metrics["timestamp_range"] = {
                "start": ts_min.isoformat(),
                "end": ts_max.isoformat(),
                "duration_minutes": duration_minutes,
            }
        else:
            metrics["timestamp_range"] = {}
            metrics["event_rate_per_minute"] = 0.0
    else:
        metrics["timestamp_range"] = {}
        metrics["event_rate_per_minute"] = 0.0

    # Top talkers
    if "src_ip" in normalized_df.columns:
        top_src = normalized_df["src_ip"].value_counts().head(10)
        metrics["top_src_ips"] = [{"ip": ip, "count": int(count)} for ip, count in top_src.items()]
    else:
        metrics["top_src_ips"] = []

    if "dst_ip" in normalized_df.columns:
        top_dst = normalized_df["dst_ip"].value_counts().head(10)
        metrics["top_dst_ips"] = [{"ip": ip, "count": int(count)} for ip, count in top_dst.items()]
    else:
        metrics["top_dst_ips"] = []

    # Top ports
    port_cols = ["src_port", "dst_port"]
    all_ports = []
    for col in port_cols:
        if col in normalized_df.columns:
            all_ports.extend(normalized_df[col].dropna().tolist())
    if all_ports:
        port_counts = pd.Series(all_ports).value_counts().head(10)
        metrics["top_ports"] = [
            {"port": int(port), "count": int(count)} for port, count in port_counts.items()
        ]
    else:
        metrics["top_ports"] = []

    # DNS stats
    dns_df = (
        normalized_df[normalized_df["event_type"] == "dns"]
        if "event_type" in normalized_df.columns
        else pd.DataFrame()
    )
    dns_stats = {}
    if not dns_df.empty:
        # Top queried domains (from metadata or dst_ip if domain-like)
        if "metadata" in dns_df.columns:
            # Try to extract domain from metadata if it's JSON
            domains = []
            for meta in dns_df["metadata"].dropna():
                if isinstance(meta, dict) and "query" in meta:
                    domains.append(meta["query"])
                elif isinstance(meta, str):
                    # Try to parse as JSON
                    try:
                        import json

                        meta_dict = json.loads(meta)
                        if "query" in meta_dict:
                            domains.append(meta_dict["query"])
                    except (json.JSONDecodeError, TypeError):
                        pass
            if domains:
                domain_counts = pd.Series(domains).value_counts().head(10)
                dns_stats["top_domains"] = [
                    {"domain": domain, "count": int(count)}
                    for domain, count in domain_counts.items()
                ]
            else:
                dns_stats["top_domains"] = []
        else:
            dns_stats["top_domains"] = []

        # NXDOMAIN ratio (if available in metadata)
        nxdomain_count = 0
        total_dns = len(dns_df)
        if "metadata" in dns_df.columns:
            for meta in dns_df["metadata"].dropna():
                if isinstance(meta, dict) and meta.get("rcode") == "NXDOMAIN":
                    nxdomain_count += 1
                elif isinstance(meta, str):
                    try:
                        import json

                        meta_dict = json.loads(meta)
                        if meta_dict.get("rcode") == "NXDOMAIN":
                            nxdomain_count += 1
                    except (json.JSONDecodeError, TypeError):
                        pass
        if total_dns > 0:
            dns_stats["nxdomain_ratio"] = nxdomain_count / total_dns
        else:
            dns_stats["nxdomain_ratio"] = 0.0

        # Unique domains per source IP
        if "src_ip" in dns_df.columns and domains:
            src_domain_counts = {}
            for idx, row in dns_df.iterrows():
                src_ip = row.get("src_ip")
                if pd.notna(src_ip):
                    meta = row.get("metadata")
                    domain = None
                    if isinstance(meta, dict) and "query" in meta:
                        domain = meta["query"]
                    elif isinstance(meta, str):
                        try:
                            import json

                            meta_dict = json.loads(meta)
                            domain = meta_dict.get("query")
                        except (json.JSONDecodeError, TypeError):
                            pass
                    if domain:
                        if src_ip not in src_domain_counts:
                            src_domain_counts[src_ip] = set()
                        src_domain_counts[src_ip].add(domain)
            if src_domain_counts:
                avg_domains_per_src = sum(
                    len(domains) for domains in src_domain_counts.values()
                ) / len(src_domain_counts)
                dns_stats["avg_unique_domains_per_src"] = avg_domains_per_src
            else:
                dns_stats["avg_unique_domains_per_src"] = 0.0
        else:
            dns_stats["avg_unique_domains_per_src"] = 0.0
    else:
        dns_stats = {
            "top_domains": [],
            "nxdomain_ratio": 0.0,
            "avg_unique_domains_per_src": 0.0,
        }
    metrics["dns_stats"] = dns_stats

    # Suricata stats
    suricata_df = (
        normalized_df[normalized_df["sensor"] == "suricata"]
        if "sensor" in normalized_df.columns
        else pd.DataFrame()
    )
    suricata_stats = {}
    if not suricata_df.empty:
        # Alert counts by signature
        if "signature" in suricata_df.columns:
            signature_counts = suricata_df["signature"].value_counts().head(10)
            suricata_stats["alerts_by_signature"] = [
                {"signature": sig, "count": int(count)} for sig, count in signature_counts.items()
            ]
        else:
            suricata_stats["alerts_by_signature"] = []

        # Alert counts by severity
        if "severity" in suricata_df.columns:
            severity_counts = suricata_df["severity"].value_counts()
            suricata_stats["alerts_by_severity"] = {
                str(sev): int(count) for sev, count in severity_counts.items()
            }
        else:
            suricata_stats["alerts_by_severity"] = {}
    else:
        suricata_stats = {"alerts_by_signature": [], "alerts_by_severity": {}}
    metrics["suricata_stats"] = suricata_stats

    return metrics


def compute_detection_quality_metrics(
    detections: list[dict[str, Any]], cases: list[dict[str, Any]], min_evidence_rows: int = 5
) -> dict[str, Any]:
    """Compute detection quality metrics.

    Args:
        detections: List of detection dictionaries
        cases: List of case dictionaries
        min_evidence_rows: Minimum evidence rows required for explainability

    Returns:
        Dictionary of detection quality metrics
    """
    metrics = {}

    # Detection counts by type
    if detections:
        detections_df = pd.DataFrame(detections)
        if "detection_type" in detections_df.columns:
            metrics["detections_by_type"] = detections_df["detection_type"].value_counts().to_dict()
        else:
            metrics["detections_by_type"] = {}
        metrics["total_detections"] = len(detections)
    else:
        metrics["detections_by_type"] = {}
        metrics["total_detections"] = 0

    # Detections over time (if timestamps available)
    if detections:
        detections_df = pd.DataFrame(detections)
        if "ts" in detections_df.columns:
            ts_series = pd.to_datetime(detections_df["ts"], errors="coerce", unit="s")
            ts_valid = ts_series.dropna()
            if not ts_valid.empty:
                metrics["detection_timeline"] = {
                    "first": ts_valid.min().isoformat(),
                    "last": ts_valid.max().isoformat(),
                    "count": len(ts_valid),
                }
            else:
                metrics["detection_timeline"] = {}
        else:
            metrics["detection_timeline"] = {}
    else:
        metrics["detection_timeline"] = {}

    # Per-case evidence count
    evidence_counts = []
    for case in cases:
        evidence = case.get("evidence", [])
        evidence_counts.append(len(evidence))

    if evidence_counts:
        metrics["case_evidence_stats"] = {
            "min": min(evidence_counts),
            "max": max(evidence_counts),
            "mean": sum(evidence_counts) / len(evidence_counts),
            "median": sorted(evidence_counts)[len(evidence_counts) // 2],
        }
    else:
        metrics["case_evidence_stats"] = {}

    # Confidence distribution
    confidences = []
    for case in cases:
        validation = case.get("validation", {})
        confidence = validation.get("confidence", 0.5)
        confidences.append(confidence)

    if confidences:
        metrics["confidence_stats"] = {
            "min": min(confidences),
            "max": max(confidences),
            "mean": sum(confidences) / len(confidences),
            "median": sorted(confidences)[len(confidences) // 2],
        }
    else:
        metrics["confidence_stats"] = {}

    # Explainability score: percentage of detections with >= N evidence rows
    explainable_count = sum(1 for count in evidence_counts if count >= min_evidence_rows)
    if cases:
        metrics["explainability_score"] = explainable_count / len(cases)
    else:
        metrics["explainability_score"] = 0.0

    return metrics


def compute_agentic_metrics(agent_trace_path: str) -> dict[str, Any]:
    """Compute agentic verification metrics from agent trace.

    Args:
        agent_trace_path: Path to agent_trace.jsonl file

    Returns:
        Dictionary of agentic metrics
    """
    import json

    metrics = {
        "critic_checks_passed": 0,
        "critic_checks_failed": 0,
        "evidence_retrieval_passes": 0,
        "agent_steps": [],
    }

    try:
        with open(agent_trace_path) as f:
            for line in f:
                if line.strip():
                    step = json.loads(line)
                    agent = step.get("agent", "")
                    step_type = step.get("step", "")
                    data = step.get("data", {})

                    metrics["agent_steps"].append(
                        {"agent": agent, "step": step_type, "data_keys": list(data.keys())}
                    )

                    # Count critic checks
                    if agent == "critic_agent":
                        if step_type == "complete":
                            cases_validated = data.get("cases_validated", 0)
                            # Assume all validated cases passed (simplified)
                            metrics["critic_checks_passed"] += cases_validated

                    # Count evidence retrieval passes
                    if agent == "evidence_agent" and step_type == "complete":
                        metrics["evidence_retrieval_passes"] += 1

    except FileNotFoundError:
        logger.warning(f"Agent trace file not found: {agent_trace_path}")
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing agent trace: {e}")

    return metrics
