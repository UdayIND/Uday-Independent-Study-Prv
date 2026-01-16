"""Report agent for generating case reports."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ReportAgent:
    """Generates case reports from evidence bundles."""

    def __init__(self, config: dict[str, Any]):
        """Initialize report agent.

        Args:
            config: Reporting configuration
        """
        self.config = config

    def generate_report(self, case: dict[str, Any]) -> str:
        """Generate markdown report for a case.

        Args:
            case: Case dictionary with evidence

        Returns:
            Markdown report string
        """
        report_lines = []

        # Executive Summary
        report_lines.append("### Executive Summary")
        report_lines.append("")
        detection_type = case.get("detection_type", "Unknown")
        src_ip = case.get("src_ip", "Unknown")
        detection_count = case.get("detection_count", 0)
        evidence_count = len(case.get("evidence", []))

        if detection_type == "recon_scanning":
            summary_text = (
                f"This case involves reconnaissance and scanning activity originating from {src_ip}. "
                f"The source IP exhibited suspicious network behavior consistent with network scanning, "
                f"including high fan-out connections to multiple destination IPs within a short time window. "
                f"{detection_count} detection(s) were generated, supported by {evidence_count} evidence rows."
            )
        elif detection_type == "dns_beaconing":
            summary_text = (
                f"This case involves DNS beaconing activity originating from {src_ip}. "
                f"The source IP exhibited suspicious DNS query patterns consistent with command and control "
                f"communication, including repeated queries to specific domains. "
                f"{detection_count} detection(s) were generated, supported by {evidence_count} evidence rows."
            )
        else:
            summary_text = (
                f"This case involves suspicious activity from {src_ip}. "
                f"{detection_count} detection(s) were generated, supported by {evidence_count} evidence rows."
            )

        report_lines.append(summary_text)
        report_lines.append("")

        # Case Details
        report_lines.append("### Case Details")
        report_lines.append("")
        report_lines.append(
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| Case ID | {case.get('case_id', 'Unknown')} |\n"
            f"| Detection Type | {detection_type} |\n"
            f"| Source IP | {src_ip} |\n"
            f"| Detection Count | {detection_count} |\n"
            f"| Evidence Rows | {evidence_count} |\n"
        )
        report_lines.append("")

        # Timeline
        if self.config.get("include_timeline", True):
            report_lines.append("### Timeline")
            report_lines.append("")
            ts_start = case.get("ts_start", None)
            ts_end = case.get("ts_end", None)

            # Format timestamps
            if ts_start:
                try:
                    from datetime import datetime

                    if isinstance(ts_start, (int, float)):
                        ts_start_str = datetime.fromtimestamp(ts_start).strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        )
                    else:
                        ts_start_str = str(ts_start)
                except Exception:
                    ts_start_str = str(ts_start)
            else:
                ts_start_str = "Unknown"

            if ts_end:
                try:
                    from datetime import datetime

                    if isinstance(ts_end, (int, float)):
                        ts_end_str = datetime.fromtimestamp(ts_end).strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        )
                    else:
                        ts_end_str = str(ts_end)
                except Exception:
                    ts_end_str = str(ts_end)
            else:
                ts_end_str = "Unknown"

            duration = None
            if (
                ts_start
                and ts_end
                and isinstance(ts_start, (int, float))
                and isinstance(ts_end, (int, float))
            ):
                duration_seconds = ts_end - ts_start
                if duration_seconds < 60:
                    duration = f"{duration_seconds:.1f} seconds"
                elif duration_seconds < 3600:
                    duration = f"{duration_seconds/60:.1f} minutes"
                else:
                    duration = f"{duration_seconds/3600:.1f} hours"

            report_lines.append(
                f"| Event | Timestamp |\n"
                f"|-------|----------|\n"
                f"| Case Start | {ts_start_str} |\n"
                f"| Case End | {ts_end_str} |\n"
            )
            if duration:
                report_lines.append(f"| Duration | {duration} |\n")
            report_lines.append("")

        # Evidence Table
        report_lines.append("### Evidence")
        report_lines.append("")

        evidence = case.get("evidence", [])
        if evidence:
            report_lines.append(
                "The following table shows the top evidence rows supporting this case:"
            )
            report_lines.append("")
            report_lines.append(
                "| Timestamp | Sensor | Event Type | Source IP | Dest IP | Ports | Signature |"
            )
            report_lines.append(
                "|-----------|--------|------------|-----------|---------|-------|-----------|"
            )

            for ev in evidence[:20]:  # Limit to top 20 rows
                ts = ev.get("ts", "N/A")
                # Format timestamp
                try:
                    from datetime import datetime

                    if isinstance(ts, (int, float)):
                        ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        ts_str = str(ts)
                except Exception:
                    ts_str = str(ts)

                sensor = ev.get("sensor", "N/A")
                event_type = ev.get("event_type", "N/A")
                src_ip = ev.get("src_ip", "N/A")
                dst_ip = ev.get("dst_ip", "N/A")
                src_port = ev.get("src_port", "")
                dst_port = ev.get("dst_port", "")
                ports = (
                    f"{src_port}:{dst_port}"
                    if src_port and dst_port
                    else f"{dst_port}"
                    if dst_port
                    else "N/A"
                )
                signature = ev.get("signature", "N/A")
                if signature and len(signature) > 40:
                    signature = signature[:37] + "..."

                report_lines.append(
                    f"| {ts_str} | {sensor} | {event_type} | {src_ip} | {dst_ip} | {ports} | {signature} |"
                )

            if len(evidence) > 20:
                report_lines.append(
                    f"\n*Showing top 20 of {len(evidence)} evidence rows. Full evidence available in events.parquet.*"
                )
        else:
            report_lines.append("*No evidence rows available for this case.*")

        report_lines.append("")

        # Detector Reasoning
        report_lines.append("### Detector Reasoning")
        report_lines.append("")
        detection_type = case.get("detection_type", "Unknown")

        if detection_type == "recon_scanning":
            report_lines.append(
                "**Why this case was flagged:**\n\n"
                "This case was flagged by the reconnaissance/scanning detector based on the following indicators:\n"
                "- High fan-out: The source IP connected to an unusually high number of unique destination IPs\n"
                "- Time concentration: Multiple connections occurred within a short time window\n"
                "- Pattern consistency: Connection patterns are consistent with network scanning behavior\n\n"
                "The detector analyzes connection logs to identify sources that exhibit scanning behavior, "
                "which may indicate reconnaissance activity preceding an attack."
            )
        elif detection_type == "dns_beaconing":
            report_lines.append(
                "**Why this case was flagged:**\n\n"
                "This case was flagged by the DNS beaconing detector based on the following indicators:\n"
                "- Repeated queries: The source IP repeatedly queried the same domain(s)\n"
                "- Query frequency: Query patterns suggest periodic communication\n"
                "- Suspicious patterns: DNS query behavior is consistent with command and control communication\n\n"
                "The detector analyzes DNS logs to identify sources that exhibit beaconing behavior, "
                "which may indicate malware command and control or data exfiltration attempts."
            )
        else:
            report_lines.append(
                f"This case was flagged by the {detection_type} detector. "
                "Review the evidence table above for specific indicators."
            )

        report_lines.append("")

        # Confidence and Limitations
        validation = case.get("validation", {})
        confidence = validation.get("confidence", 0.5)

        report_lines.append("### Confidence & Limitations")
        report_lines.append("")
        report_lines.append(f"**Confidence Score:** {confidence:.2f} ({confidence*100:.0f}%)")

        # Confidence interpretation
        if confidence >= 0.8:
            conf_level = "High"
        elif confidence >= 0.6:
            conf_level = "Medium"
        else:
            conf_level = "Low"
        report_lines.append(f"**Confidence Level:** {conf_level}")
        report_lines.append("")

        report_lines.append("**Limitations:**")
        report_lines.append(
            "- Analysis is based on baseline detection algorithms with configurable thresholds"
        )
        report_lines.append("- Limited to available telemetry data (Zeek and Suricata logs)")
        report_lines.append(
            "- Network context (internal vs external IPs) may require additional investigation"
        )
        report_lines.append("- False positives are possible; manual review recommended")
        report_lines.append("- Additional endpoint or application logs may provide more context")
        report_lines.append("")

        # Defensive Actions
        report_lines.append("### Recommended Defensive Actions")
        report_lines.append("")
        report_lines.append("1. **Network Monitoring:**")
        report_lines.append("   - Monitor traffic from source IP for continued suspicious activity")
        report_lines.append("   - Review firewall logs for related connections")
        report_lines.append("")
        report_lines.append("2. **Endpoint Investigation:**")
        report_lines.append("   - Check endpoint logs for processes associated with source IP")
        report_lines.append("   - Review system logs for unusual activity")
        report_lines.append("")
        report_lines.append("3. **DNS Analysis:**")
        if case.get("detection_type") == "dns_beaconing":
            report_lines.append("   - Review DNS query patterns for identified domains")
            report_lines.append("   - Consider blocking suspicious domains if confirmed malicious")
        else:
            report_lines.append("   - Review DNS logs for related queries")
        report_lines.append("")
        report_lines.append("4. **Documentation:**")
        report_lines.append("   - Document findings in incident tracking system")
        report_lines.append("   - Escalate to senior analyst if confidence threshold exceeded")
        report_lines.append("")

        return "\n".join(report_lines)
