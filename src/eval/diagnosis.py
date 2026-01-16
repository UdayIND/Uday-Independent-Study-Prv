"""Generate diagnosis report when no detections are found."""

import logging
from pathlib import Path
from typing import Any

import pandas as pd

from src.eval.metrics import compute_data_health_metrics

logger = logging.getLogger(__name__)


def generate_no_detections_diagnosis(
    normalized_df: pd.DataFrame,
    detector_config: dict[str, Any],
    output_path: Path,
) -> None:
    """Generate diagnosis report when no detections are found.

    Args:
        normalized_df: Normalized events DataFrame
        detector_config: Detector configuration dictionary
        output_path: Path to save diagnosis markdown file
    """
    logger.info("Generating no-detections diagnosis report...")

    # Compute data health metrics
    data_health = compute_data_health_metrics(normalized_df)

    lines = []
    lines.append("# No Detections Diagnosis Report")
    lines.append("")
    lines.append(
        "This report analyzes why no detections were generated and provides recommendations for threshold adjustments."
    )
    lines.append("")

    # Root cause analysis
    total_events = data_health.get("total_events", 0)
    if total_events == 0:
        lines.append("## ⚠️ Root Cause: No Events Parsed")
        lines.append("")
        lines.append(
            "**No events were parsed from the PCAP file.** This is the primary reason no detections were generated."
        )
        lines.append("")
        lines.append("**Possible causes:**")
        lines.append(
            "1. Zeek/Suricata did not produce log files (check `data/derived/zeek/` and `data/derived/suricata/`)"
        )
        lines.append("2. PCAP file is empty or corrupted")
        lines.append("3. PCAP file contains no network traffic")
        lines.append("4. Docker containers failed to process the PCAP")
        lines.append("")
        lines.append("**Next steps:**")
        lines.append("- Verify PCAP file is valid: `file data/raw/<your_pcap>.pcap`")
        lines.append(
            "- Check Docker logs: `docker compose logs zeek` and `docker compose logs suricata`"
        )
        lines.append("- Try a different PCAP file with known malicious traffic")
        lines.append("- Ensure Docker is running: `docker info`")
        lines.append("")
    else:
        lines.append("## Root Cause Analysis")
        lines.append("")
        lines.append(f"**Total Events Available**: {total_events}")
        lines.append("")
        lines.append(
            "Events were parsed but did not trigger any detectors. See detector analysis below for threshold comparisons."
        )
        lines.append("")

    # Traffic Summary
    lines.append("## Traffic Summary")
    lines.append("")
    lines.append(f"- **Total Events**: {data_health.get('total_events', 0)}")
    lines.append(
        f"- **Event Rate**: {data_health.get('event_rate_per_minute', 0.0):.2f} events/minute"
    )

    sensor_counts = data_health.get("sensor_counts", {})
    if sensor_counts:
        lines.append("- **Sensor Distribution**:")
        for sensor, count in sensor_counts.items():
            lines.append(f"  - {sensor}: {count} events")

    event_type_counts = data_health.get("event_type_counts", {})
    if event_type_counts:
        lines.append("- **Event Type Distribution**:")
        for event_type, count in event_type_counts.items():
            lines.append(f"  - {event_type}: {count} events")

    lines.append("")

    # Top Talkers
    lines.append("### Top Source IPs")
    lines.append("")
    top_src_ips = data_health.get("top_src_ips", [])
    if top_src_ips:
        lines.append("| IP Address | Event Count |")
        lines.append("|------------|-------------|")
        for ip_info in top_src_ips[:10]:
            lines.append(f"| {ip_info['ip']} | {ip_info['count']} |")
    else:
        lines.append("*No source IP data available.*")
    lines.append("")

    lines.append("### Top Destination IPs")
    lines.append("")
    top_dst_ips = data_health.get("top_dst_ips", [])
    if top_dst_ips:
        lines.append("| IP Address | Event Count |")
        lines.append("|------------|-------------|")
        for ip_info in top_dst_ips[:10]:
            lines.append(f"| {ip_info['ip']} | {ip_info['count']} |")
    else:
        lines.append("*No destination IP data available.*")
    lines.append("")

    # Top Ports
    lines.append("### Top Ports")
    lines.append("")
    top_ports = data_health.get("top_ports", [])
    if top_ports:
        lines.append("| Port | Event Count |")
        lines.append("|------|-------------|")
        for port_info in top_ports[:10]:
            lines.append(f"| {port_info['port']} | {port_info['count']} |")
    else:
        lines.append("*No port data available.*")
    lines.append("")

    # DNS Stats
    dns_stats = data_health.get("dns_stats", {})
    if dns_stats:
        lines.append("### DNS Statistics")
        lines.append("")
        top_domains = dns_stats.get("top_domains", [])
        if top_domains:
            lines.append("**Top Queried Domains:**")
            lines.append("")
            lines.append("| Domain | Query Count |")
            lines.append("|--------|-------------|")
            for domain_info in top_domains[:10]:
                lines.append(f"| {domain_info['domain']} | {domain_info['count']} |")
            lines.append("")
        nxdomain_ratio = dns_stats.get("nxdomain_ratio", 0.0)
        lines.append(f"- **NXDOMAIN Ratio**: {nxdomain_ratio:.2%}")
        lines.append("")

    # Suricata Stats
    suricata_stats = data_health.get("suricata_stats", {})
    if suricata_stats:
        lines.append("### Suricata Alerts")
        lines.append("")
        alerts_by_sig = suricata_stats.get("alerts_by_signature", [])
        if alerts_by_sig:
            lines.append("**Top Alerts by Signature:**")
            lines.append("")
            lines.append("| Signature | Alert Count |")
            lines.append("|-----------|-------------|")
            for alert_info in alerts_by_sig[:10]:
                lines.append(f"| {alert_info['signature']} | {alert_info['count']} |")
            lines.append("")
        else:
            lines.append("*No Suricata alerts found.*")
            lines.append("")

    # Detector Analysis
    lines.append("## Detector Analysis")
    lines.append("")

    recon_config = detector_config.get("recon_scanning", {})
    dns_config = detector_config.get("dns_beaconing", {})

    if recon_config.get("enabled", False):
        lines.append("### Recon/Scanning Detector")
        lines.append("")
        lines.append("**Current Thresholds:**")
        lines.append(
            f"- Fan-out threshold: {recon_config.get('fan_out_threshold', 'N/A')} unique destination IPs"
        )
        lines.append(f"- Burst threshold: {recon_config.get('burst_threshold', 'N/A')} connections")
        lines.append(f"- Time window: {recon_config.get('time_window_seconds', 'N/A')} seconds")
        lines.append("")

        # Analyze why it didn't trigger
        if normalized_df.empty:
            lines.append("**Why it didn't trigger:** No events available for analysis.")
        else:
            # Check actual fan-out
            if "src_ip" in normalized_df.columns and "dst_ip" in normalized_df.columns:
                conn_df = (
                    normalized_df[normalized_df["event_type"] == "conn"]
                    if "event_type" in normalized_df.columns
                    else normalized_df
                )
                if not conn_df.empty:
                    fan_out_per_src = conn_df.groupby("src_ip")["dst_ip"].nunique()
                    max_fan_out = fan_out_per_src.max() if not fan_out_per_src.empty else 0
                    lines.append(
                        f"**Actual maximum fan-out observed**: {max_fan_out} unique destination IPs"
                    )
                    if max_fan_out < recon_config.get("fan_out_threshold", 50):
                        lines.append(
                            f"  → Threshold ({recon_config.get('fan_out_threshold', 50)}) is too high. "
                            f"Maximum observed is {max_fan_out}."
                        )
                    lines.append("")
        lines.append("")

    if dns_config.get("enabled", False):
        lines.append("### DNS Beaconing Detector")
        lines.append("")
        lines.append("**Current Thresholds:**")
        lines.append(
            f"- Repeated query threshold: {dns_config.get('repeated_query_threshold', 'N/A')} queries"
        )
        lines.append(
            f"- NXDOMAIN ratio threshold: {dns_config.get('nxdomain_ratio_threshold', 'N/A')}"
        )
        lines.append(f"- Time window: {dns_config.get('time_window_seconds', 'N/A')} seconds")
        lines.append("")

        # Analyze why it didn't trigger
        if normalized_df.empty:
            lines.append("**Why it didn't trigger:** No events available for analysis.")
        else:
            dns_df = (
                normalized_df[normalized_df["event_type"] == "dns"]
                if "event_type" in normalized_df.columns
                else pd.DataFrame()
            )
            if dns_df.empty:
                lines.append("**Why it didn't trigger:** No DNS events found in the dataset.")
            else:
                lines.append(f"**DNS events found**: {len(dns_df)}")
                nxdomain_ratio = dns_stats.get("nxdomain_ratio", 0.0)
                lines.append(f"**Actual NXDOMAIN ratio**: {nxdomain_ratio:.2%}")
                if nxdomain_ratio < dns_config.get("nxdomain_ratio_threshold", 0.3):
                    lines.append(
                        f"  → Threshold ({dns_config.get('nxdomain_ratio_threshold', 0.3):.2%}) is too high. "
                        f"Actual ratio is {nxdomain_ratio:.2%}."
                    )
        lines.append("")

    # Recommendations
    lines.append("## Recommended Threshold Adjustments")
    lines.append("")
    lines.append("To generate detections, try the following threshold adjustments:")
    lines.append("")

    if recon_config.get("enabled", False):
        current_fan_out = recon_config.get("fan_out_threshold", 50)
        recommended_fan_out = max(5, int(current_fan_out * 0.2))  # 20% of current, minimum 5
        lines.append("### Recon/Scanning Detector")
        lines.append("")
        lines.append("**Recommended adjustments:**")
        lines.append(
            f"- Reduce `fan_out_threshold` from {current_fan_out} to {recommended_fan_out}"
        )
        lines.append(
            f"- Reduce `burst_threshold` from {recon_config.get('burst_threshold', 100)} to {max(10, int(recon_config.get('burst_threshold', 100) * 0.2))}"
        )
        lines.append("")

    if dns_config.get("enabled", False):
        current_repeated = dns_config.get("repeated_query_threshold", 10)
        recommended_repeated = max(3, int(current_repeated * 0.3))  # 30% of current, minimum 3
        current_nxdomain = dns_config.get("nxdomain_ratio_threshold", 0.3)
        recommended_nxdomain = max(0.1, current_nxdomain * 0.5)  # 50% of current, minimum 0.1
        lines.append("### DNS Beaconing Detector")
        lines.append("")
        lines.append("**Recommended adjustments:**")
        lines.append(
            f"- Reduce `repeated_query_threshold` from {current_repeated} to {recommended_repeated}"
        )
        lines.append(
            f"- Reduce `nxdomain_ratio_threshold` from {current_nxdomain:.2f} to {recommended_nxdomain:.2f}"
        )
        lines.append("")

    # Re-run command
    lines.append("## Re-run Command")
    lines.append("")
    lines.append("After adjusting thresholds in `configs/detector.yaml`, re-run the pipeline:")
    lines.append("")
    lines.append("```bash")
    lines.append("make run PCAP=data/raw/<your_pcap>.pcap")
    lines.append("```")
    lines.append("")
    lines.append("Or use the tuning mode to automatically find working thresholds:")
    lines.append("")
    lines.append("```bash")
    lines.append("make tune PCAP=data/raw/<your_pcap>.pcap")
    lines.append("```")
    lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    logger.info(f"Saved no-detections diagnosis to {output_path}")
