"""Generate matplotlib plots for evaluation metrics.

Includes both operational plots and publication-quality research visualizations.
All plots use RESEARCH_DPI (300) and consistent RESEARCH_COLORS.
"""

import logging
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Patch

logger = logging.getLogger(__name__)

# Publication-quality defaults
RESEARCH_DPI = 300
RESEARCH_COLORS = {
    "primary": "#2c3e50",
    "secondary": "#e74c3c",
    "success": "#27ae60",
    "warning": "#f39c12",
    "info": "#3498db",
    "muted": "#95a5a6",
}
RESEARCH_PALETTE = ["#2c3e50", "#e74c3c", "#27ae60", "#f39c12", "#3498db", "#95a5a6",
                    "#8e44ad", "#1abc9c", "#d35400", "#2980b9"]


def _set_research_style():
    """Apply consistent research styling to current figure."""
    plt.rcParams.update({
        "font.size": 11,
        "axes.titlesize": 14,
        "axes.labelsize": 12,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
    })


def plot_events_per_minute(normalized_df: pd.DataFrame, output_path: Path) -> None:
    """Plot events per minute over time."""
    if normalized_df.empty or "ts" not in normalized_df.columns:
        logger.warning("Cannot plot events per minute: missing data or timestamp column")
        return

    ts_series = pd.to_datetime(normalized_df["ts"], errors="coerce", unit="s")
    ts_valid = ts_series.dropna()
    if ts_valid.empty:
        logger.warning("No valid timestamps for events per minute plot")
        return

    _set_research_style()
    ts_valid.index = ts_valid
    events_per_minute = ts_valid.resample("1min").count()

    fig, ax = plt.subplots(figsize=(10, 6))

    if len(events_per_minute) <= 1:
        ax.bar(range(len(events_per_minute)), events_per_minute.values,
               color=RESEARCH_COLORS["primary"], edgecolor="black", width=0.5)
        ax.set_xticks(range(len(events_per_minute)))
        ax.set_xticklabels([str(t)[:19] for t in events_per_minute.index], rotation=45, ha="right")
        total = int(events_per_minute.values[0]) if len(events_per_minute) > 0 else 0
        ax.annotate(f"N={total} events\n(single time window)",
                    xy=(0, total), xytext=(0.3, total * 0.8),
                    fontsize=11, fontweight="bold", color=RESEARCH_COLORS["info"])
    else:
        ax.plot(events_per_minute.index, events_per_minute.values,
                linewidth=2, color=RESEARCH_COLORS["primary"], marker="o", markersize=4)
        ax.fill_between(events_per_minute.index, events_per_minute.values,
                         alpha=0.15, color=RESEARCH_COLORS["primary"])

    ax.set_xlabel("Time")
    ax.set_ylabel("Events per Minute")
    ax.set_title("Events per Minute Over Time", fontweight="bold")
    ax.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_top_ips(normalized_df: pd.DataFrame, column: str, output_path: Path, title: str) -> None:
    """Plot top IPs by count."""
    if normalized_df.empty or column not in normalized_df.columns:
        logger.warning(f"Cannot plot top {column}: missing data or column")
        return

    top_ips = normalized_df[column].value_counts().head(10)
    if top_ips.empty:
        logger.warning(f"No data for top {column} plot")
        return

    _set_research_style()
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = [RESEARCH_PALETTE[i % len(RESEARCH_PALETTE)] for i in range(len(top_ips))]
    bars = ax.barh(range(len(top_ips)), top_ips.values, color=colors, edgecolor="black", alpha=0.85)
    ax.set_yticks(range(len(top_ips)))
    ax.set_yticklabels(top_ips.index)
    ax.set_xlabel("Event Count")
    ax.set_ylabel("IP Address")
    ax.set_title(title, fontweight="bold")
    ax.invert_yaxis()

    for bar, val in zip(bars, top_ips.values):
        ax.text(bar.get_width() + max(top_ips.values) * 0.01, bar.get_y() + bar.get_height() / 2,
                str(int(val)), va="center", fontsize=9, color=RESEARCH_COLORS["primary"])

    ax.grid(True, alpha=0.3, axis="x")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_protocol_breakdown(normalized_df: pd.DataFrame, output_path: Path) -> None:
    """Plot protocol breakdown as pie chart."""
    if normalized_df.empty or "proto" not in normalized_df.columns:
        logger.warning("Cannot plot protocol breakdown: missing data or proto column")
        return

    proto_counts = normalized_df["proto"].value_counts()
    if proto_counts.empty:
        logger.warning("No protocol data for breakdown plot")
        return

    _set_research_style()
    fig, ax = plt.subplots(figsize=(8, 8))
    colors = RESEARCH_PALETTE[:len(proto_counts)]
    wedges, texts, autotexts = ax.pie(
        proto_counts.values,
        labels=proto_counts.index,
        colors=colors,
        autopct="%1.1f%%",
        startangle=90,
        pctdistance=0.85,
        wedgeprops=dict(edgecolor="white", linewidth=2),
    )
    for autotext in autotexts:
        autotext.set_fontsize(10)
        autotext.set_fontweight("bold")
    ax.set_title("Protocol Breakdown", fontweight="bold")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_dns_top_domains(dns_stats: dict[str, Any], output_path: Path) -> None:
    """Plot top DNS domains."""
    top_domains = dns_stats.get("top_domains", [])
    if not top_domains:
        logger.warning("No DNS domain data for plot")
        return

    domains = [d["domain"] for d in top_domains]
    counts = [d["count"] for d in top_domains]

    _set_research_style()
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = [RESEARCH_PALETTE[i % len(RESEARCH_PALETTE)] for i in range(len(domains))]
    bars = ax.barh(range(len(domains)), counts, color=colors, edgecolor="black", alpha=0.85)
    ax.set_yticks(range(len(domains)))
    ax.set_yticklabels(domains)
    ax.set_xlabel("Query Count")
    ax.set_ylabel("Domain")
    ax.set_title("Top DNS Domains", fontweight="bold")
    ax.invert_yaxis()
    ax.grid(True, alpha=0.3, axis="x")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_suricata_alerts_by_signature(suricata_stats: dict[str, Any], output_path: Path) -> None:
    """Plot Suricata alerts by signature (top 10)."""
    alerts = suricata_stats.get("alerts_by_signature", [])
    if not alerts:
        logger.warning("No Suricata alert data for plot")
        return

    signatures = [a["signature"] for a in alerts[:10]]
    counts = [a["count"] for a in alerts[:10]]

    _set_research_style()
    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.barh(range(len(signatures)), counts, color=RESEARCH_COLORS["secondary"],
                   edgecolor="black", alpha=0.85)
    ax.set_yticks(range(len(signatures)))
    ax.set_yticklabels(signatures)
    ax.set_xlabel("Alert Count")
    ax.set_ylabel("Signature")
    ax.set_title("Top 10 Suricata Alerts by Signature", fontweight="bold")
    ax.invert_yaxis()
    ax.grid(True, alpha=0.3, axis="x")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_detections_over_time(detections: list[dict[str, Any]], output_path: Path) -> None:
    """Plot detections over time."""
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

    _set_research_style()
    fig, ax = plt.subplots(figsize=(10, 6))

    if len(ts_valid) <= 2:
        # Few detections: show as scatter with event markers
        det_types = detections_df.get("detection_type", pd.Series(["unknown"] * len(detections_df)))
        unique_types = det_types.unique()
        for i, dt in enumerate(unique_types):
            mask = det_types == dt
            color = RESEARCH_PALETTE[i % len(RESEARCH_PALETTE)]
            ax.scatter(ts_valid[mask], [1] * mask.sum(), s=200, c=color, marker="D",
                      edgecolors="black", zorder=5, label=dt)
        ax.set_yticks([1])
        ax.set_yticklabels(["Detection"])
        ax.annotate(f"N={len(ts_valid)} detection(s)", xy=(0.02, 0.95),
                   xycoords="axes fraction", fontsize=11, fontweight="bold",
                   color=RESEARCH_COLORS["info"])
    else:
        ts_valid.index = ts_valid
        detections_per_minute = ts_valid.resample("1min").count()
        ax.plot(detections_per_minute.index, detections_per_minute.values,
                marker="o", linewidth=2, color=RESEARCH_COLORS["secondary"], markersize=6)
        ax.set_ylabel("Detections per Minute")

    ax.set_xlabel("Time")
    ax.set_title("Detections Over Time", fontweight="bold")
    ax.grid(True, alpha=0.3)
    if ax.get_legend_handles_labels()[1]:
        ax.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_detections_by_type(detections: list[dict[str, Any]], output_path: Path) -> None:
    """Plot detections by type."""
    if not detections:
        logger.warning("No detections for type breakdown plot")
        return

    detections_df = pd.DataFrame(detections)
    if "detection_type" not in detections_df.columns:
        logger.warning("Cannot plot detections by type: missing detection_type column")
        return

    type_counts = detections_df["detection_type"].value_counts()

    _set_research_style()
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = [RESEARCH_PALETTE[i % len(RESEARCH_PALETTE)] for i in range(len(type_counts))]
    bars = ax.bar(range(len(type_counts)), type_counts.values, color=colors,
                  edgecolor="black", width=0.6, alpha=0.85)
    ax.set_xticks(range(len(type_counts)))
    ax.set_xticklabels(type_counts.index, rotation=45, ha="right")
    ax.set_xlabel("Detection Type")
    ax.set_ylabel("Count")
    ax.set_title("Detections by Type", fontweight="bold")
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))

    for bar, val in zip(bars, type_counts.values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                str(int(val)), ha="center", va="bottom", fontsize=11, fontweight="bold")

    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_cases_by_confidence(cases: list[dict[str, Any]], output_path: Path) -> None:
    """Plot cases by confidence score."""
    if not cases:
        logger.warning("No cases for confidence plot")
        return

    confidences = []
    case_ids = []
    for case in cases:
        validation = case.get("validation", {})
        confidence = validation.get("confidence", 0.5)
        confidences.append(confidence)
        case_ids.append(case.get("case_id", "?"))

    if not confidences:
        logger.warning("No confidence scores for plot")
        return

    _set_research_style()
    fig, ax = plt.subplots(figsize=(10, 6))

    if len(confidences) <= 3:
        # Few cases: bar chart per case instead of histogram
        colors = [RESEARCH_COLORS["success"] if c >= 0.6 else
                  RESEARCH_COLORS["warning"] if c >= 0.4 else
                  RESEARCH_COLORS["secondary"] for c in confidences]
        bars = ax.bar(range(len(case_ids)), confidences, color=colors,
                      edgecolor="black", width=0.5, alpha=0.85)
        ax.set_xticks(range(len(case_ids)))
        ax.set_xticklabels(case_ids, rotation=45, ha="right")
        ax.set_xlabel("Case ID")
        ax.axhline(y=0.6, color=RESEARCH_COLORS["muted"], linestyle="--",
                   linewidth=1.5, label="Threshold (0.6)")
        for bar, val in zip(bars, confidences):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.2f}", ha="center", va="bottom", fontsize=11, fontweight="bold")
    else:
        ax.hist(confidences, bins=10, edgecolor="black", alpha=0.7,
                color=RESEARCH_COLORS["info"])
        ax.axvline(x=0.6, color=RESEARCH_COLORS["secondary"], linestyle="--",
                   linewidth=2, label="Threshold (0.6)")
        ax.set_xlabel("Confidence Score")

    ax.set_ylabel("Number of Cases")
    ax.set_title("Cases by Confidence Score", fontweight="bold")
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.legend()
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_compression_ratio(soc_metrics: dict[str, Any], output_path: Path) -> None:
    """Plot alert-to-case compression ratio."""
    raw = soc_metrics.get("raw_detections", 0)
    cases = soc_metrics.get("assembled_cases", 0)

    if raw == 0 and cases == 0:
        logger.warning("No detections or cases for compression ratio plot")
        return

    _set_research_style()
    labels = ["Raw Detections", "Assembled Cases"]
    values = [raw, cases]
    colors = [RESEARCH_COLORS["secondary"], RESEARCH_COLORS["success"]]

    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.bar(labels, values, color=colors, edgecolor="black", width=0.5, alpha=0.85)

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(values) * 0.02,
            str(val),
            ha="center", va="bottom", fontweight="bold", fontsize=14,
        )

    ratio = soc_metrics.get("compression_ratio", 0.0)
    ax.set_title(f"Alert-to-Case Compression (Ratio: {ratio:.1f}:1)", fontweight="bold")
    ax.set_ylabel("Count")
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_evidence_completeness(
    cases: list[dict[str, Any]], min_evidence: int, output_path: Path
) -> None:
    """Plot evidence completeness per case."""
    if not cases:
        logger.warning("No cases for evidence completeness plot")
        return

    case_ids = []
    evidence_counts = []
    for case in cases:
        case_ids.append(case.get("case_id", "?"))
        evidence_counts.append(len(case.get("evidence", [])))

    _set_research_style()
    colors = [RESEARCH_COLORS["success"] if c >= min_evidence else RESEARCH_COLORS["secondary"]
              for c in evidence_counts]

    fig, ax = plt.subplots(figsize=(10, max(4, len(cases) * 0.6)))
    bars = ax.barh(range(len(case_ids)), evidence_counts, color=colors,
                   edgecolor="black", alpha=0.85)
    ax.set_yticks(range(len(case_ids)))
    ax.set_yticklabels(case_ids)
    ax.axvline(x=min_evidence, color=RESEARCH_COLORS["warning"], linestyle="--",
               linewidth=2, label=f"Threshold ({min_evidence})")

    for bar, val in zip(bars, evidence_counts):
        ax.text(bar.get_width() + max(evidence_counts) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                str(int(val)), va="center", fontsize=10, fontweight="bold")

    ax.set_xlabel("Evidence Row Count")
    ax.set_ylabel("Case ID")
    ax.set_title("Evidence Completeness per Case", fontweight="bold")
    ax.legend()
    ax.invert_yaxis()
    ax.grid(True, alpha=0.3, axis="x")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_fp_proxy_comparison(
    benchmark_results: list[dict[str, Any]], output_path: Path
) -> None:
    """Plot false positive proxy comparison across benchmark PCAPs."""
    if not benchmark_results:
        logger.warning("No benchmark results for FP proxy comparison plot")
        return

    # Filter out skipped/failed PCAPs
    active = [r for r in benchmark_results if r.get("status", "success") == "success"
              and r.get("total_events", 0) > 0]
    if not active:
        logger.warning("No active benchmark results for FP proxy plot")
        return

    _set_research_style()
    names = []
    values = []
    colors = []

    for result in active:
        fp = result.get("fp_proxy_detections_per_hour")
        if fp is None:
            fp = 0.0
        names.append(result.get("name", "?"))
        values.append(fp)
        colors.append(RESEARCH_COLORS["success"] if result.get("label") == "benign"
                      else RESEARCH_COLORS["secondary"])

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.bar(range(len(names)), values, color=colors, edgecolor="black", alpha=0.85)
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, rotation=45, ha="right")
    ax.set_xlabel("PCAP")
    ax.set_ylabel("Detections per Hour")
    ax.set_title("False Positive Proxy: Detections per Hour by PCAP", fontweight="bold")

    legend_elements = [
        Patch(facecolor=RESEARCH_COLORS["secondary"], edgecolor="black", label="Malicious"),
        Patch(facecolor=RESEARCH_COLORS["success"], edgecolor="black", label="Benign"),
    ]
    ax.legend(handles=legend_elements)
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


# ---- Publication-Quality Research Plots ----


def plot_detection_confusion_matrix(
    ground_truth_metrics: dict[str, Any], output_path: Path
) -> None:
    """Plot confusion matrix heatmap for ground truth evaluation."""
    if not ground_truth_metrics or ground_truth_metrics.get("pcap_label") == "unknown":
        logger.warning("No ground truth metrics for confusion matrix plot")
        return

    _set_research_style()
    per_type = ground_truth_metrics.get("per_type_metrics", {})
    if not per_type:
        tp = ground_truth_metrics.get("true_positives", 0)
        fp = ground_truth_metrics.get("false_positives", 0)
        fn = ground_truth_metrics.get("false_negatives", 0)
        matrix = np.array([[tp, fp], [fn, 0]])
        labels = ["Detected", "Not Detected"]
        col_labels = ["Actually Malicious", "Actually Benign"]
    else:
        types = sorted(per_type.keys())
        matrix_data = []
        for dt in types:
            m = per_type[dt]
            matrix_data.append([m.get("true_positives", 0), m.get("false_positives", 0), m.get("false_negatives", 0)])
        matrix = np.array(matrix_data)
        labels = types
        col_labels = ["TP", "FP", "FN"]

    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto")

    ax.set_xticks(range(len(col_labels)))
    ax.set_xticklabels(col_labels, fontsize=12)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=12)

    for i in range(len(labels)):
        for j in range(len(col_labels)):
            ax.text(j, i, str(int(matrix[i, j])),
                    ha="center", va="center", fontsize=14, fontweight="bold",
                    color="white" if matrix[i, j] > matrix.max() / 2 else "black")

    ax.set_title("Detection Confusion Matrix", fontsize=14, fontweight="bold")
    fig.colorbar(im, ax=ax, label="Count")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_confidence_distribution(cases: list[dict[str, Any]], output_path: Path) -> None:
    """Plot histogram of case confidence scores with threshold and mean lines."""
    if not cases:
        logger.warning("No cases for confidence distribution plot")
        return

    confidences = []
    for case in cases:
        validation = case.get("validation", {})
        conf = validation.get("confidence", 0.0)
        confidences.append(conf)

    if not confidences:
        return

    _set_research_style()
    fig, ax = plt.subplots(figsize=(10, 6))

    if len(confidences) <= 3:
        # Too few for histogram - show bar chart per case
        case_ids = [c.get("case_id", f"Case {i+1}") for i, c in enumerate(cases)]
        colors = [RESEARCH_COLORS["success"] if c >= 0.6 else RESEARCH_COLORS["warning"]
                  for c in confidences]
        bars = ax.bar(range(len(case_ids)), confidences, color=colors,
                      edgecolor="black", width=0.5, alpha=0.85)
        ax.set_xticks(range(len(case_ids)))
        ax.set_xticklabels(case_ids, rotation=45, ha="right")
        for bar, val in zip(bars, confidences):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.2f}", ha="center", va="bottom", fontsize=11, fontweight="bold")
        ax.set_ylim(0, 1.1)
    else:
        ax.hist(
            confidences, bins=20, range=(0, 1),
            edgecolor="black", alpha=0.7, color=RESEARCH_COLORS["info"],
            label="Cases", density=False
        )

    ax.axvline(x=0.6, color=RESEARCH_COLORS["secondary"], linestyle="--",
               linewidth=2, label="Confidence Threshold (0.6)")

    mean_conf = np.mean(confidences)
    ax.axvline(x=mean_conf, color=RESEARCH_COLORS["success"], linestyle="-.",
               linewidth=2, label=f"Mean ({mean_conf:.2f})")

    ax.set_xlabel("Confidence Score", fontsize=12)
    ax.set_ylabel("Number of Cases", fontsize=12)
    ax.set_title("Case Confidence Distribution", fontsize=14, fontweight="bold")
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_ablation_comparison(ablation_results: dict[str, Any], output_path: Path) -> None:
    """Plot grouped bar chart comparing ablation configurations."""
    configs = ablation_results.get("configs", {})
    if not configs:
        logger.warning("No ablation configs for comparison plot")
        return

    _set_research_style()
    config_names = list(configs.keys())
    metrics_to_plot = ["detections", "cases", "compression_ratio", "evidence_completeness", "mean_confidence"]
    metric_labels = ["Detections", "Cases", "Compression Ratio", "Evidence Completeness", "Mean Confidence"]

    x = np.arange(len(config_names))
    width = 0.15
    colors = [RESEARCH_COLORS["primary"], RESEARCH_COLORS["secondary"],
              RESEARCH_COLORS["info"], RESEARCH_COLORS["success"], RESEARCH_COLORS["warning"]]

    fig, ax = plt.subplots(figsize=(14, 7))

    for i, (metric, label) in enumerate(zip(metrics_to_plot, metric_labels)):
        values = []
        for cfg_name in config_names:
            cfg = configs[cfg_name]
            val = cfg.get(metric, 0)
            if val is None:
                val = 0
            values.append(float(val))

        bars = ax.bar(x + i * width, values, width, label=label, color=colors[i],
                      edgecolor="black", alpha=0.85)

        for bar, val in zip(bars, values):
            if val > 0:
                text = f"{val:.2f}" if val != int(val) else str(int(val))
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                       text, ha="center", va="bottom", fontsize=8)

    ax.set_xlabel("Configuration", fontsize=12)
    ax.set_ylabel("Value", fontsize=12)
    ax.set_title("Ablation Study: Configuration Comparison", fontsize=14, fontweight="bold")
    ax.set_xticks(x + width * 2)
    ax.set_xticklabels(config_names, rotation=30, ha="right", fontsize=11)
    ax.legend(fontsize=9, loc="upper right")
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_benchmark_radar(benchmark_results: list[dict[str, Any]], output_path: Path) -> None:
    """Plot radar/spider chart comparing per-PCAP metric profiles."""
    if not benchmark_results or len(benchmark_results) < 2:
        logger.warning("Need at least 2 benchmark results for radar plot")
        return

    _set_research_style()
    metrics = ["Detections", "Cases", "Compression", "Evidence\nCompleteness", "FP Proxy\n(inv)"]
    N = len(metrics)
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(polar=True))

    for idx, result in enumerate(benchmark_results):
        soc = result.get("soc_metrics", {})
        det = result.get("detection_quality", {})

        total_det = det.get("total_detections", 0)
        cases = soc.get("assembled_cases", 0)
        compression = min(1.0, soc.get("compression_ratio", 0) / 10.0)
        evidence = soc.get("evidence_completeness", 0) or 0
        fp_proxy = soc.get("fp_proxy_detections_per_hour", 0)
        fp_inv = max(0, 1.0 - min(1.0, fp_proxy / 100.0))

        values = [
            min(1.0, total_det / 10.0),
            min(1.0, cases / 5.0),
            compression,
            evidence,
            fp_inv,
        ]
        values += values[:1]

        color = RESEARCH_PALETTE[idx % len(RESEARCH_PALETTE)]
        name = result.get("name", f"PCAP {idx}")
        ax.plot(angles, values, linewidth=2, color=color, label=name)
        ax.fill(angles, values, alpha=0.1, color=color)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metrics, fontsize=11)
    ax.set_ylim(0, 1)
    ax.set_title("Benchmark PCAP Metric Profiles", fontsize=14, fontweight="bold", pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.0), fontsize=10)
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_agent_pipeline_sankey(
    events_count: int,
    detections_count: int,
    cases_count: int,
    validated_count: int,
    output_path: Path,
) -> None:
    """Plot pipeline funnel chart showing data flow through stages."""
    stages = ["Events", "Detections", "Cases", "Validated\nCases"]
    values = [events_count, detections_count, cases_count, validated_count]
    colors = [RESEARCH_COLORS["muted"], RESEARCH_COLORS["warning"],
              RESEARCH_COLORS["info"], RESEARCH_COLORS["success"]]

    _set_research_style()
    fig, ax = plt.subplots(figsize=(12, 6))

    bars = ax.bar(range(len(stages)), values, color=colors, edgecolor="black", width=0.6)

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(values) * 0.02,
            str(val),
            ha="center", va="bottom", fontsize=14, fontweight="bold"
        )

    for i in range(len(stages) - 1):
        if values[i] > 0:
            reduction = ((values[i] - values[i + 1]) / values[i]) * 100
            # Cap display at 99.9% to avoid misleading "-100%"
            if reduction >= 100:
                reduction = 99.9
            mid_y = min(values[i], values[i + 1]) / 2
            ax.annotate(
                f"-{reduction:.1f}%",
                xy=(i + 0.5, mid_y),
                fontsize=11, ha="center", color=RESEARCH_COLORS["secondary"],
                fontweight="bold"
            )

    ax.set_xticks(range(len(stages)))
    ax.set_xticklabels(stages, fontsize=12)
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("Pipeline Funnel: Events to Validated Cases", fontsize=14, fontweight="bold")
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


# ---- New Research Plot Types ----


def plot_confidence_factor_breakdown(cases: list[dict[str, Any]], output_path: Path) -> None:
    """Plot stacked bar chart showing 5 confidence factors per case.

    Args:
        cases: List of case dictionaries with validation.factor_scores
        output_path: Path to save PNG file
    """
    if not cases:
        logger.warning("No cases for confidence factor breakdown plot")
        return

    factor_names = ["detection_strength", "evidence_volume", "sensor_diversity",
                    "temporal_concentration", "cross_case_correlation"]
    factor_labels = ["Detection\nStrength", "Evidence\nVolume", "Sensor\nDiversity",
                     "Temporal\nConc.", "Cross-Case\nCorr."]

    case_ids = []
    factor_data = {f: [] for f in factor_names}
    has_factors = False

    for case in cases:
        case_ids.append(case.get("case_id", "?"))
        validation = case.get("validation", {})
        factor_scores = validation.get("factor_scores", {})
        if factor_scores:
            has_factors = True
        for f in factor_names:
            factor_data[f].append(factor_scores.get(f, 0.0))

    if not has_factors:
        logger.warning("No factor scores available in cases for breakdown plot")
        return

    _set_research_style()
    fig, ax = plt.subplots(figsize=(12, 7))
    x = np.arange(len(case_ids))
    width = 0.15
    colors = [RESEARCH_COLORS["primary"], RESEARCH_COLORS["info"],
              RESEARCH_COLORS["success"], RESEARCH_COLORS["warning"],
              RESEARCH_COLORS["secondary"]]

    for i, (factor, label) in enumerate(zip(factor_names, factor_labels)):
        values = factor_data[factor]
        ax.bar(x + i * width, values, width, label=label, color=colors[i],
               edgecolor="black", alpha=0.85)

    ax.set_xlabel("Case ID", fontsize=12)
    ax.set_ylabel("Factor Score (0-1)", fontsize=12)
    ax.set_title("Confidence Factor Breakdown per Case", fontsize=14, fontweight="bold")
    ax.set_xticks(x + width * 2)
    ax.set_xticklabels(case_ids, rotation=45, ha="right")
    ax.set_ylim(0, 1.1)
    ax.legend(fontsize=9, loc="upper right", ncol=2)
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_detection_signal_heatmap(detections: list[dict[str, Any]], output_path: Path) -> None:
    """Plot heatmap of detection signal strengths.

    Args:
        detections: List of detection dictionaries with metadata signal scores
        output_path: Path to save PNG file
    """
    if not detections:
        logger.warning("No detections for signal heatmap")
        return

    recon_signals = ["fan_out_score", "burst_score", "failed_conn_score"]
    dns_signals = ["repeat_score", "periodicity_score", "nxdomain_score"]

    rows = []
    labels = []
    all_signals = set()
    for i, det in enumerate(detections):
        det_type = det.get("detection_type", "unknown")
        src_ip = det.get("src_ip", "?")
        metadata = det.get("metadata", {})
        if isinstance(metadata, str):
            try:
                import json
                metadata = json.loads(metadata)
            except (ValueError, TypeError):
                metadata = {}

        signals = recon_signals if det_type == "recon_scanning" else dns_signals
        row = {}
        for s in signals:
            val = metadata.get(s, 0.0)
            if val is not None:
                row[s] = float(val)
                all_signals.add(s)
        if row:
            rows.append(row)
            labels.append(f"{src_ip}\n({det_type})")

    if not rows or not all_signals:
        logger.warning("No signal data available for heatmap")
        return

    _set_research_style()
    all_signals = sorted(all_signals)
    matrix = np.zeros((len(rows), len(all_signals)))
    for i, row in enumerate(rows):
        for j, sig in enumerate(all_signals):
            matrix[i, j] = row.get(sig, 0.0)

    fig, ax = plt.subplots(figsize=(max(8, len(all_signals) * 2), max(4, len(rows) * 1.2)))
    im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto", vmin=0, vmax=1)

    ax.set_xticks(range(len(all_signals)))
    ax.set_xticklabels([s.replace("_", "\n") for s in all_signals], fontsize=10)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=10)

    for i in range(len(rows)):
        for j in range(len(all_signals)):
            val = matrix[i, j]
            ax.text(j, i, f"{val:.2f}", ha="center", va="center", fontsize=11,
                    fontweight="bold", color="white" if val > 0.5 else "black")

    ax.set_title("Detection Signal Strength Heatmap", fontsize=14, fontweight="bold")
    fig.colorbar(im, ax=ax, label="Signal Strength (0-1)", shrink=0.8)
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_threshold_sensitivity(
    normalized_df: pd.DataFrame, output_path: Path,
    current_fan_out: int = 15, current_burst: int = 20,
    current_repeat: int = 5, current_nxdomain: float = 0.15,
) -> None:
    """Plot sensitivity analysis: detection count vs threshold parameters.

    Sweeps recon and DNS detector thresholds to show which parameters
    most influence detection outcomes. Marks current operating point.

    Args:
        normalized_df: Normalized events DataFrame
        output_path: Path to save PNG file
        current_fan_out: Current fan_out_threshold setting
        current_burst: Current burst_threshold setting
        current_repeat: Current repeated_query_threshold setting
        current_nxdomain: Current nxdomain_ratio_threshold setting
    """
    if normalized_df.empty:
        logger.warning("Cannot plot threshold sensitivity: empty DataFrame")
        return

    _set_research_style()

    try:
        from src.detect_baseline.detector import BaselineDetector
    except ImportError:
        logger.warning("Cannot import BaselineDetector for sensitivity analysis")
        return

    # Sweep recon thresholds
    fan_out_range = list(range(5, 105, 5))
    burst_range = list(range(5, 105, 5))
    recon_grid = np.zeros((len(burst_range), len(fan_out_range)))

    for bi, burst in enumerate(burst_range):
        for fi, fan_out in enumerate(fan_out_range):
            config = {
                "recon_scanning": {
                    "enabled": True,
                    "time_window_seconds": 120,
                    "fan_out_threshold": fan_out,
                    "burst_threshold": burst,
                    "failed_connection_ratio": 0.4,
                },
                "dns_beaconing": {"enabled": False},
            }
            try:
                detector = BaselineDetector(config)
                detections = detector.detect(normalized_df)
                recon_grid[bi, fi] = len(detections)
            except Exception:
                recon_grid[bi, fi] = 0

    # Sweep DNS thresholds
    repeat_range = list(range(2, 22, 2))
    nxdomain_range = [round(x, 2) for x in np.arange(0.05, 0.55, 0.05)]
    dns_grid = np.zeros((len(nxdomain_range), len(repeat_range)))

    for ni, nxdomain in enumerate(nxdomain_range):
        for ri, repeat in enumerate(repeat_range):
            config = {
                "recon_scanning": {"enabled": False},
                "dns_beaconing": {
                    "enabled": True,
                    "time_window_seconds": 300,
                    "repeated_query_threshold": repeat,
                    "periodicity_window_seconds": 1800,
                    "nxdomain_ratio_threshold": nxdomain,
                    "min_unique_domains": 3,
                },
            }
            try:
                detector = BaselineDetector(config)
                detections = detector.detect(normalized_df)
                dns_grid[ni, ri] = len(detections)
            except Exception:
                dns_grid[ni, ri] = 0

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

    # Recon heatmap
    im1 = ax1.imshow(recon_grid, aspect="auto", cmap="YlOrRd", origin="lower")
    ax1.set_xticks(range(0, len(fan_out_range), 2))
    ax1.set_xticklabels([str(f) for f in fan_out_range[::2]])
    ax1.set_yticks(range(0, len(burst_range), 2))
    ax1.set_yticklabels([str(b) for b in burst_range[::2]])
    ax1.set_xlabel("Fan-out Threshold")
    ax1.set_ylabel("Burst Threshold")
    ax1.set_title("Recon Detection Sensitivity", fontweight="bold")
    plt.colorbar(im1, ax=ax1, label="Detection Count")

    # Mark current operating point
    if current_fan_out in fan_out_range and current_burst in burst_range:
        fi = fan_out_range.index(current_fan_out)
        bi = burst_range.index(current_burst)
        ax1.plot(fi, bi, "k*", markersize=15, label=f"Current ({current_fan_out}, {current_burst})")
        ax1.legend(fontsize=9)

    # DNS heatmap
    im2 = ax2.imshow(dns_grid, aspect="auto", cmap="YlOrRd", origin="lower")
    ax2.set_xticks(range(0, len(repeat_range), 2))
    ax2.set_xticklabels([str(r) for r in repeat_range[::2]])
    ax2.set_yticks(range(0, len(nxdomain_range), 2))
    ax2.set_yticklabels([f"{n:.2f}" for n in nxdomain_range[::2]])
    ax2.set_xlabel("Repeated Query Threshold")
    ax2.set_ylabel("NXDOMAIN Ratio Threshold")
    ax2.set_title("DNS Beaconing Detection Sensitivity", fontweight="bold")
    plt.colorbar(im2, ax=ax2, label="Detection Count")

    # Mark current operating point
    if current_repeat in repeat_range:
        ri = repeat_range.index(current_repeat)
        closest_nx = min(range(len(nxdomain_range)), key=lambda i: abs(nxdomain_range[i] - current_nxdomain))
        ax2.plot(ri, closest_nx, "k*", markersize=15, label=f"Current ({current_repeat}, {current_nxdomain})")
        ax2.legend(fontsize=9)

    plt.suptitle("Threshold Sensitivity Analysis", fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()


def plot_cross_pcap_confidence_comparison(
    benchmark_results: list[dict[str, Any]], output_path: Path
) -> None:
    """Plot box/violin plot of confidence scores across different PCAPs.

    Args:
        benchmark_results: List of per-PCAP result dicts with confidence info
        output_path: Path to save PNG file
    """
    if not benchmark_results:
        logger.warning("No benchmark results for cross-PCAP confidence comparison")
        return

    _set_research_style()
    names = []
    confidence_lists = []
    label_colors = []

    for result in benchmark_results:
        if result.get("status") != "success":
            continue
        name = result.get("name", "?")
        label = result.get("label", "unknown")
        # Get confidence values from the run
        conf_stats = result.get("confidence_stats", {})
        mean_conf = conf_stats.get("mean", 0)

        # If we have individual case confidences, use them
        case_confidences = result.get("case_confidences", [])
        if not case_confidences and mean_conf > 0:
            case_confidences = [mean_conf]

        if case_confidences:
            names.append(name)
            confidence_lists.append(case_confidences)
            label_colors.append(RESEARCH_COLORS["secondary"] if label == "malicious"
                               else RESEARCH_COLORS["success"])

    if not names:
        logger.warning("No confidence data for cross-PCAP comparison")
        return

    fig, ax = plt.subplots(figsize=(12, 6))

    bp = ax.boxplot(confidence_lists, patch_artist=True, widths=0.6,
                    medianprops=dict(color="black", linewidth=2))
    for patch, color in zip(bp["boxes"], label_colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    ax.axhline(y=0.6, color=RESEARCH_COLORS["muted"], linestyle="--",
               linewidth=1.5, label="Decision Threshold (0.6)")
    ax.set_xticks(range(1, len(names) + 1))
    ax.set_xticklabels(names, rotation=45, ha="right")
    ax.set_xlabel("PCAP", fontsize=12)
    ax.set_ylabel("Confidence Score", fontsize=12)
    ax.set_title("Cross-PCAP Confidence Comparison", fontsize=14, fontweight="bold")
    ax.set_ylim(0, 1.05)

    legend_elements = [
        Patch(facecolor=RESEARCH_COLORS["secondary"], alpha=0.7, edgecolor="black", label="Malicious"),
        Patch(facecolor=RESEARCH_COLORS["success"], alpha=0.7, edgecolor="black", label="Benign"),
    ]
    ax.legend(handles=legend_elements, fontsize=10)
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(output_path, dpi=RESEARCH_DPI, bbox_inches="tight")
    plt.close()
