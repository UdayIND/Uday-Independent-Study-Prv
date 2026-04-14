"""Main evaluator that orchestrates metrics computation and plot generation."""

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

from src.eval.metrics import (
    compute_agentic_metrics,
    compute_data_health_metrics,
    compute_detection_quality_metrics,
    compute_ground_truth_metrics,
    compute_soc_metrics,
)
from src.eval.plots import (
    plot_agent_pipeline_sankey,
    plot_cases_by_confidence,
    plot_compression_ratio,
    plot_confidence_distribution,
    plot_confidence_factor_breakdown,
    plot_detection_confusion_matrix,
    plot_detection_signal_heatmap,
    plot_detections_by_type,
    plot_detections_over_time,
    plot_dns_top_domains,
    plot_events_per_minute,
    plot_evidence_completeness,
    plot_protocol_breakdown,
    plot_suricata_alerts_by_signature,
    plot_threshold_sensitivity,
    plot_top_ips,
)

logger = logging.getLogger(__name__)


class Evaluator:
    """Evaluates pipeline outputs and generates metrics and visualizations."""

    def __init__(self, run_dir: Path, config: dict[str, Any] | None = None):
        """Initialize evaluator.

        Args:
            run_dir: Directory containing run outputs
            config: Optional configuration dictionary
        """
        self.run_dir = Path(run_dir)
        self.config = config or {}
        self.figures_dir = self.run_dir / "figures"
        self.figures_dir.mkdir(exist_ok=True)

    def evaluate(
        self,
        normalized_df: pd.DataFrame,
        detections: list[dict[str, Any]],
        cases: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Run complete evaluation.

        Args:
            normalized_df: Normalized events DataFrame
            detections: List of detection dictionaries
            cases: List of case dictionaries

        Returns:
            Complete evaluation summary dictionary
        """
        logger.info("Starting evaluation...")

        # Compute metrics
        data_health = compute_data_health_metrics(normalized_df)
        min_evidence_rows = self.config.get("case_assembly", {}).get("min_evidence_rows", 5)
        detection_quality = compute_detection_quality_metrics(detections, cases, min_evidence_rows)

        agent_trace_path = self.run_dir / "agent_trace.jsonl"
        agentic_metrics = compute_agentic_metrics(str(agent_trace_path))

        pcap_label = self.config.get("pcap_label", "unknown")
        soc_metrics = compute_soc_metrics(detections, cases, normalized_df, pcap_label)

        # Ground truth metrics
        expected_sources = self.config.get("expected_sources", None)
        ground_truth_metrics = compute_ground_truth_metrics(
            detections, pcap_label, expected_sources, normalized_df
        )

        # Combine all metrics
        evaluation_summary = {
            "data_health": data_health,
            "detection_quality": detection_quality,
            "agentic_metrics": agentic_metrics,
            "soc_metrics": soc_metrics,
            "ground_truth_metrics": ground_truth_metrics,
        }

        # Generate plots
        logger.info("Generating plots...")
        self._generate_plots(
            normalized_df, detections, cases, data_health, detection_quality,
            soc_metrics, ground_truth_metrics
        )

        # Save evaluation summary
        summary_path = self.run_dir / "evaluation_summary.json"
        with open(summary_path, "w") as f:
            json.dump(evaluation_summary, f, indent=2, default=str)
        logger.info(f"Saved evaluation summary to {summary_path}")

        # Generate markdown report
        report_path = self.run_dir / "evaluation_report.md"
        self._generate_report(evaluation_summary, report_path)
        logger.info(f"Saved evaluation report to {report_path}")

        return evaluation_summary

    def _generate_plots(
        self,
        normalized_df: pd.DataFrame,
        detections: list[dict[str, Any]],
        cases: list[dict[str, Any]],
        data_health: dict[str, Any],
        detection_quality: dict[str, Any],
        soc_metrics: dict[str, Any],
        ground_truth_metrics: dict[str, Any] | None = None,
    ) -> None:
        """Generate all plots including publication-quality research visualizations.

        Args:
            normalized_df: Normalized events DataFrame
            detections: List of detection dictionaries
            cases: List of case dictionaries
            data_health: Data health metrics
            detection_quality: Detection quality metrics
            soc_metrics: SOC-specific metrics
            ground_truth_metrics: Optional ground truth evaluation metrics
        """
        # 1. Events per minute
        plot_events_per_minute(normalized_df, self.figures_dir / "events_per_minute.png")

        # 2. Top source IPs
        plot_top_ips(
            normalized_df,
            "src_ip",
            self.figures_dir / "top_src_ips.png",
            "Top 10 Source IPs by Event Count",
        )

        # 3. Top destination IPs
        plot_top_ips(
            normalized_df,
            "dst_ip",
            self.figures_dir / "top_dst_ips.png",
            "Top 10 Destination IPs by Event Count",
        )

        # 4. Protocol breakdown
        plot_protocol_breakdown(normalized_df, self.figures_dir / "protocol_breakdown.png")

        # 5. DNS top domains
        dns_stats = data_health.get("dns_stats", {})
        plot_dns_top_domains(dns_stats, self.figures_dir / "dns_top_domains.png")

        # 6. Suricata alerts by signature
        suricata_stats = data_health.get("suricata_stats", {})
        plot_suricata_alerts_by_signature(
            suricata_stats, self.figures_dir / "suricata_alerts_by_signature.png"
        )

        # 7. Detections over time
        plot_detections_over_time(detections, self.figures_dir / "detections_over_time.png")

        # 8. Detections by type
        plot_detections_by_type(detections, self.figures_dir / "detections_by_type.png")

        # 9. Cases by confidence
        plot_cases_by_confidence(cases, self.figures_dir / "cases_by_confidence.png")

        # 10. Compression ratio
        plot_compression_ratio(soc_metrics, self.figures_dir / "compression_ratio.png")

        # 11. Evidence completeness
        min_evidence = self.config.get("case_assembly", {}).get("min_evidence_rows", 5)
        plot_evidence_completeness(cases, min_evidence, self.figures_dir / "evidence_completeness.png")

        # 12. Confusion matrix (if ground truth available)
        if ground_truth_metrics and ground_truth_metrics.get("pcap_label") != "unknown":
            plot_detection_confusion_matrix(
                ground_truth_metrics, self.figures_dir / "confusion_matrix.png"
            )

        # 13. Confidence distribution
        plot_confidence_distribution(cases, self.figures_dir / "confidence_distribution.png")

        # 14. Pipeline funnel
        validated_count = sum(
            1 for c in cases
            if c.get("validation", {}).get("is_valid", False)
        )
        plot_agent_pipeline_sankey(
            events_count=len(normalized_df),
            detections_count=len(detections),
            cases_count=len(cases),
            validated_count=validated_count,
            output_path=self.figures_dir / "pipeline_funnel.png",
        )

        # 15. Confidence factor breakdown (if factor scores available)
        plot_confidence_factor_breakdown(cases, self.figures_dir / "confidence_factor_breakdown.png")

        # 16. Detection signal heatmap
        plot_detection_signal_heatmap(detections, self.figures_dir / "detection_signal_heatmap.png")

        # 17. Threshold sensitivity analysis
        detector_config = self.config.get("detectors", {})
        recon_config = detector_config.get("recon_scanning", {})
        dns_config = detector_config.get("dns_beaconing", {})
        plot_threshold_sensitivity(
            normalized_df,
            self.figures_dir / "threshold_sensitivity.png",
            current_fan_out=recon_config.get("fan_out_threshold", 15),
            current_burst=recon_config.get("burst_threshold", 20),
            current_repeat=dns_config.get("repeated_query_threshold", 5),
            current_nxdomain=dns_config.get("nxdomain_ratio_threshold", 0.15),
        )

    def _generate_report(self, evaluation_summary: dict[str, Any], output_path: Path) -> None:
        """Generate markdown evaluation report.

        Args:
            evaluation_summary: Complete evaluation summary
            output_path: Path to save markdown report
        """
        lines = []
        lines.append("# Pipeline Evaluation Report")
        lines.append("")

        # Data Health Section
        lines.append("## Data Health")
        lines.append("")
        data_health = evaluation_summary.get("data_health", {})
        lines.append(f"- **Total Events**: {data_health.get('total_events', 0)}")
        lines.append(
            f"- **Event Rate**: {data_health.get('event_rate_per_minute', 0.0):.2f} events/minute"
        )

        sensor_counts = data_health.get("sensor_counts", {})
        if sensor_counts:
            lines.append("- **Sensor Distribution**:")
            for sensor, count in sensor_counts.items():
                lines.append(f"  - {sensor}: {count}")

        missing_rates = data_health.get("missing_value_rates", {})
        if missing_rates:
            lines.append("- **Missing Value Rates**:")
            for field, rate in missing_rates.items():
                lines.append(f"  - {field}: {rate:.2%}")

        lines.append("")

        # Detection Quality Section
        lines.append("## Detection Quality")
        lines.append("")
        detection_quality = evaluation_summary.get("detection_quality", {})
        lines.append(f"- **Total Detections**: {detection_quality.get('total_detections', 0)}")

        detections_by_type = detection_quality.get("detections_by_type", {})
        if detections_by_type:
            lines.append("- **Detections by Type**:")
            for det_type, count in detections_by_type.items():
                lines.append(f"  - {det_type}: {count}")

        explainability = detection_quality.get("explainability_score", 0.0)
        lines.append(f"- **Explainability Score**: {explainability:.2%}")

        confidence_stats = detection_quality.get("confidence_stats", {})
        if confidence_stats:
            lines.append("- **Confidence Statistics**:")
            lines.append(f"  - Mean: {confidence_stats.get('mean', 0.0):.2f}")
            lines.append(f"  - Median: {confidence_stats.get('median', 0.0):.2f}")
            lines.append(f"  - Min: {confidence_stats.get('min', 0.0):.2f}")
            lines.append(f"  - Max: {confidence_stats.get('max', 0.0):.2f}")

        lines.append("")

        # SOC Metrics Section
        lines.append("## SOC Triage Metrics")
        lines.append("")
        soc_metrics = evaluation_summary.get("soc_metrics", {})
        lines.append(
            f"- **Alert-to-Case Compression Ratio**: "
            f"{soc_metrics.get('compression_ratio', 0.0):.2f} "
            f"({soc_metrics.get('raw_detections', 0)} detections -> "
            f"{soc_metrics.get('assembled_cases', 0)} cases)"
        )
        ev_comp = soc_metrics.get("evidence_completeness")
        ev_comp_str = f"{ev_comp:.2%}" if ev_comp is not None else "N/A (no cases)"
        lines.append(f"- **Evidence Completeness**: {ev_comp_str}")
        fp_proxy = soc_metrics.get("fp_proxy_detections_per_hour")
        if fp_proxy is not None:
            lines.append(f"- **FP Proxy (detections/hour)**: {fp_proxy:.2f}")
        pcap_label = soc_metrics.get("pcap_label", "unknown")
        lines.append(f"- **PCAP Label**: {pcap_label}")
        lines.append("")

        # Ground Truth Section
        ground_truth = evaluation_summary.get("ground_truth_metrics", {})
        if ground_truth.get("pcap_label") != "unknown":
            lines.append("## Ground Truth Evaluation")
            lines.append("")
            lines.append(f"- **PCAP Label**: {ground_truth.get('pcap_label')}")
            lines.append(f"- **True Positives**: {ground_truth.get('true_positives', 0)}")
            lines.append(f"- **False Positives**: {ground_truth.get('false_positives', 0)}")
            lines.append(f"- **False Negatives**: {ground_truth.get('false_negatives', 0)}")
            if ground_truth.get("precision") is not None:
                lines.append(f"- **Precision**: {ground_truth['precision']:.4f}")
            if ground_truth.get("recall") is not None:
                lines.append(f"- **Recall**: {ground_truth['recall']:.4f}")
            if ground_truth.get("f1_score") is not None:
                lines.append(f"- **F1 Score**: {ground_truth['f1_score']:.4f}")
            if ground_truth.get("detection_latency_seconds") is not None:
                lines.append(
                    f"- **Detection Latency**: {ground_truth['detection_latency_seconds']:.2f}s"
                )
            lines.append("")

        # Agentic Metrics Section
        lines.append("## Agentic Verification")
        lines.append("")
        agentic_metrics = evaluation_summary.get("agentic_metrics", {})
        lines.append(
            f"- **Critic Checks Passed**: {agentic_metrics.get('critic_checks_passed', 0)}"
        )
        lines.append(
            f"- **Evidence Retrieval Passes**: {agentic_metrics.get('evidence_retrieval_passes', 0)}"
        )

        lines.append("")

        # Figures Section
        lines.append("## Visualizations")
        lines.append("")
        figure_files = [
            "events_per_minute.png",
            "top_src_ips.png",
            "top_dst_ips.png",
            "protocol_breakdown.png",
            "dns_top_domains.png",
            "suricata_alerts_by_signature.png",
            "detections_over_time.png",
            "detections_by_type.png",
            "cases_by_confidence.png",
            "compression_ratio.png",
            "evidence_completeness.png",
            "confusion_matrix.png",
            "confidence_distribution.png",
            "pipeline_funnel.png",
            "confidence_factor_breakdown.png",
            "detection_signal_heatmap.png",
            "threshold_sensitivity.png",
        ]

        for fig_file in figure_files:
            fig_path = self.figures_dir / fig_file
            if fig_path.exists():
                fig_name = fig_file.replace("_", " ").replace(".png", "").title()
                lines.append(f"### {fig_name}")
                lines.append("")
                lines.append(f"![{fig_name}](figures/{fig_file})")
                lines.append("")

        with open(output_path, "w") as f:
            f.write("\n".join(lines))
