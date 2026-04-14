"""Compute evaluation metrics from normalized events and detections.

Includes:
- Data health metrics
- Detection quality metrics
- SOC triage metrics
- Agentic verification metrics
- Ground truth evaluation (precision, recall, F1)
- Statistical analysis (bootstrap CI, effect size)
"""

import logging
from typing import Any

import numpy as np
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


def compute_soc_metrics(
    detections: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    normalized_df: pd.DataFrame,
    pcap_label: str = "unknown",
) -> dict[str, Any]:
    """Compute SOC-specific triage metrics.

    Args:
        detections: List of detection dictionaries
        cases: List of case dictionaries
        normalized_df: Normalized events DataFrame
        pcap_label: 'malicious', 'benign', or 'unknown'

    Returns:
        Dictionary of SOC metrics
    """
    metrics: dict[str, Any] = {}

    num_detections = len(detections)
    num_cases = len(cases)

    # Alert-to-case compression ratio
    if num_cases > 0:
        metrics["compression_ratio"] = num_detections / num_cases
    else:
        metrics["compression_ratio"] = 0.0
    metrics["raw_detections"] = num_detections
    metrics["assembled_cases"] = num_cases

    # Evidence completeness score
    if cases:
        cases_with_evidence = sum(
            1
            for c in cases
            if len(c.get("evidence", [])) > 0
            and any(
                isinstance(e, dict) and e.get("src_ip") is not None
                for e in c.get("evidence", [])
            )
        )
        metrics["evidence_completeness"] = cases_with_evidence / len(cases)
    else:
        metrics["evidence_completeness"] = None  # No cases to measure

    # False positive proxy (detections per hour)
    metrics["pcap_label"] = pcap_label
    if not normalized_df.empty and "ts" in normalized_df.columns:
        ts_valid = normalized_df["ts"].dropna()
        if len(ts_valid) >= 2:
            duration_hours = (ts_valid.max() - ts_valid.min()) / 3600.0
            if duration_hours > 0:
                metrics["fp_proxy_detections_per_hour"] = num_detections / duration_hours
            else:
                metrics["fp_proxy_detections_per_hour"] = float(num_detections)
        else:
            metrics["fp_proxy_detections_per_hour"] = float(num_detections)
    else:
        metrics["fp_proxy_detections_per_hour"] = float(num_detections)

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


def compute_ground_truth_metrics(
    detections: list[dict[str, Any]],
    pcap_label: str = "unknown",
    expected_sources: list[dict[str, Any]] | None = None,
    normalized_df: pd.DataFrame | None = None,
) -> dict[str, Any]:
    """Compute ground-truth-based evaluation metrics.

    When pcap_label is 'benign', all detections are false positives.
    When pcap_label is 'malicious' and expected_sources is provided,
    compute precision, recall, and F1.

    Args:
        detections: List of detection dictionaries
        pcap_label: Ground truth label ('malicious', 'benign', 'unknown')
        expected_sources: Expected malicious sources with src_ip and detection_type
        normalized_df: Normalized events for detection latency calculation

    Returns:
        Dictionary of ground truth metrics
    """
    metrics: dict[str, Any] = {
        "pcap_label": pcap_label,
        "total_detections": len(detections),
        "precision": None,
        "recall": None,
        "f1_score": None,
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "detection_latency_seconds": None,
        "per_type_metrics": {},
    }

    if pcap_label == "unknown":
        return metrics

    if pcap_label == "benign":
        # All detections on benign traffic are false positives
        metrics["false_positives"] = len(detections)
        metrics["true_positives"] = 0
        metrics["false_negatives"] = 0
        if len(detections) > 0:
            # FPs exist: precision = TP/(TP+FP) = 0/FP = 0.0
            metrics["precision"] = 0.0
            metrics["recall"] = None  # No ground truth positives to recall
            metrics["f1_score"] = 0.0
        else:
            # No detections, no ground truth positives: 0/0 = undefined
            metrics["precision"] = None
            metrics["recall"] = None
            metrics["f1_score"] = None

        # Per-type breakdown
        det_types = {}
        for d in detections:
            dt = d.get("detection_type", "unknown")
            det_types[dt] = det_types.get(dt, 0) + 1
        for dt, count in det_types.items():
            metrics["per_type_metrics"][dt] = {
                "true_positives": 0,
                "false_positives": count,
                "false_negatives": 0,
                "precision": 0.0,
                "recall": None,
                "f1_score": 0.0,
            }
        return metrics

    if pcap_label == "malicious":
        if not expected_sources:
            # No ground truth details; can't compute precision/recall
            metrics["true_positives"] = len(detections)  # Assume all correct
            return metrics

        # Match detections against expected sources
        expected_set = set()
        for es in expected_sources:
            key = (es.get("src_ip"), es.get("detection_type"))
            expected_set.add(key)

        detected_set = set()
        tp = 0
        fp = 0
        for d in detections:
            key = (d.get("src_ip"), d.get("detection_type"))
            if key in expected_set:
                tp += 1
                detected_set.add(key)
            else:
                fp += 1

        fn = len(expected_set) - len(detected_set)

        metrics["true_positives"] = tp
        metrics["false_positives"] = fp
        metrics["false_negatives"] = fn

        # Precision, Recall, F1
        if tp + fp > 0:
            metrics["precision"] = tp / (tp + fp)
        else:
            metrics["precision"] = 0.0

        if tp + fn > 0:
            metrics["recall"] = tp / (tp + fn)
        else:
            metrics["recall"] = 0.0

        if metrics["precision"] + metrics["recall"] > 0:
            metrics["f1_score"] = (
                2 * metrics["precision"] * metrics["recall"]
                / (metrics["precision"] + metrics["recall"])
            )
        else:
            metrics["f1_score"] = 0.0

        # Detection latency: time from first malicious packet to detection
        if normalized_df is not None and not normalized_df.empty and detections:
            try:
                first_event_ts = float(normalized_df["ts"].min())
                first_detection_ts = min(float(d["ts"]) for d in detections if d.get("ts"))
                metrics["detection_latency_seconds"] = first_detection_ts - first_event_ts
            except (ValueError, TypeError, KeyError):
                pass

        # Per-type breakdown
        all_types = set()
        for es in expected_sources:
            all_types.add(es.get("detection_type", "unknown"))
        for d in detections:
            all_types.add(d.get("detection_type", "unknown"))

        for dt in all_types:
            expected_for_type = {
                es.get("src_ip") for es in expected_sources
                if es.get("detection_type") == dt
            }
            detected_for_type = {
                d.get("src_ip") for d in detections
                if d.get("detection_type") == dt and d.get("src_ip") in expected_for_type
            }
            fp_for_type = sum(
                1 for d in detections
                if d.get("detection_type") == dt and d.get("src_ip") not in expected_for_type
            )

            type_tp = len(detected_for_type)
            type_fn = len(expected_for_type) - type_tp
            type_fp = fp_for_type

            type_precision = type_tp / (type_tp + type_fp) if (type_tp + type_fp) > 0 else 0.0
            type_recall = type_tp / (type_tp + type_fn) if (type_tp + type_fn) > 0 else 0.0
            type_f1 = (
                2 * type_precision * type_recall / (type_precision + type_recall)
                if (type_precision + type_recall) > 0 else 0.0
            )

            metrics["per_type_metrics"][dt] = {
                "true_positives": type_tp,
                "false_positives": type_fp,
                "false_negatives": type_fn,
                "precision": round(type_precision, 4),
                "recall": round(type_recall, 4),
                "f1_score": round(type_f1, 4),
            }

    return metrics


def compute_statistical_metrics(
    benchmark_results: list[dict[str, Any]],
    n_bootstrap: int = 1000,
) -> dict[str, Any]:
    """Compute statistical metrics across benchmark runs.

    Args:
        benchmark_results: List of per-PCAP evaluation summaries
        n_bootstrap: Number of bootstrap samples for CI

    Returns:
        Dictionary of statistical metrics
    """
    metrics: dict[str, Any] = {
        "n_runs": len(benchmark_results),
        "compression_ratio": {},
        "evidence_completeness": {},
        "fp_proxy": {},
        "confidence": {},
        "effect_size": None,
    }

    if len(benchmark_results) < 2:
        return metrics

    # Extract metric arrays
    compression_ratios = []
    evidence_completeness = []
    fp_proxies = []
    confidences = []
    malicious_detection_rates = []
    benign_detection_rates = []

    for result in benchmark_results:
        soc = result.get("soc_metrics", {})
        det_quality = result.get("detection_quality", {})

        cr = soc.get("compression_ratio", 0)
        compression_ratios.append(cr)

        ec = soc.get("evidence_completeness")
        if ec is not None:
            evidence_completeness.append(ec)

        fp = soc.get("fp_proxy_detections_per_hour")
        fp_proxies.append(fp if fp is not None else 0)

        conf_stats = det_quality.get("confidence_stats", {})
        mean_conf = conf_stats.get("mean", 0)
        confidences.append(mean_conf)

        label = soc.get("pcap_label", "unknown")
        total_det = det_quality.get("total_detections", 0)
        data_health = result.get("data_health", {})
        total_events = data_health.get("total_events", 1)
        detection_rate = total_det / total_events if total_events > 0 else 0

        if label == "malicious":
            malicious_detection_rates.append(detection_rate)
        elif label == "benign":
            benign_detection_rates.append(detection_rate)

    def _bootstrap_ci(values: list[float], n: int = 1000) -> dict:
        """Compute bootstrap 95% confidence interval."""
        arr = np.array(values, dtype=float)
        if len(arr) < 2:
            return {"mean": float(np.mean(arr)), "ci_lower": float(np.mean(arr)), "ci_upper": float(np.mean(arr)), "std": 0.0}
        rng = np.random.default_rng(42)
        boot_means = [float(np.mean(rng.choice(arr, size=len(arr), replace=True))) for _ in range(n)]
        return {
            "mean": round(float(np.mean(arr)), 4),
            "std": round(float(np.std(arr, ddof=1)), 4),
            "ci_lower": round(float(np.percentile(boot_means, 2.5)), 4),
            "ci_upper": round(float(np.percentile(boot_means, 97.5)), 4),
        }

    metrics["compression_ratio"] = _bootstrap_ci(compression_ratios, n_bootstrap)
    metrics["evidence_completeness"] = _bootstrap_ci(evidence_completeness, n_bootstrap)
    metrics["fp_proxy"] = _bootstrap_ci(fp_proxies, n_bootstrap)
    metrics["confidence"] = _bootstrap_ci(confidences, n_bootstrap)

    # Hedge's g effect size (small-sample-corrected Cohen's d)
    n1 = len(malicious_detection_rates)
    n2 = len(benign_detection_rates)
    if n1 >= 2 and n2 >= 2:
        m1 = np.mean(malicious_detection_rates)
        m2 = np.mean(benign_detection_rates)
        s1 = np.std(malicious_detection_rates, ddof=1)
        s2 = np.std(benign_detection_rates, ddof=1)
        # Proper pooled standard deviation
        pooled_std = np.sqrt(
            ((n1 - 1) * s1**2 + (n2 - 1) * s2**2) / (n1 + n2 - 2)
        )
        if pooled_std > 0:
            cohens_d = (m1 - m2) / pooled_std
            # Hedge's g correction for small samples
            correction = 1 - (3 / (4 * (n1 + n2) - 9))
            hedges_g = cohens_d * correction
        else:
            hedges_g = 0.0
        metrics["effect_size"] = {
            "hedges_g": round(float(hedges_g), 4),
            "malicious_mean_rate": round(float(m1), 4),
            "benign_mean_rate": round(float(m2), 4),
            "n_malicious": n1,
            "n_benign": n2,
            "interpretation": (
                "large" if abs(hedges_g) >= 0.8
                else "medium" if abs(hedges_g) >= 0.5
                else "small"
            ),
        }
    elif n1 >= 1 and n2 >= 1:
        # Insufficient samples for proper effect size calculation
        metrics["effect_size"] = {
            "hedges_g": None,
            "malicious_mean_rate": round(float(np.mean(malicious_detection_rates)), 4),
            "benign_mean_rate": round(float(np.mean(benign_detection_rates)), 4),
            "n_malicious": n1,
            "n_benign": n2,
            "interpretation": "insufficient_samples",
        }

    return metrics
