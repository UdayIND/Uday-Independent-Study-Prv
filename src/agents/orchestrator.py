"""Agent orchestrator for multi-agent case assembly and reporting."""

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

from src.agents.critic_agent import CriticAgent
from src.agents.evidence_agent import EvidenceAgent
from src.agents.report_agent import ReportAgent
from src.agents.triage_agent import TriageAgent

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """Orchestrates multiple agents for case assembly and reporting."""

    def __init__(
        self,
        normalized_df: pd.DataFrame,
        detections: pd.DataFrame,
        case_config: dict[str, Any],
        output_dir: Path,
    ):
        """Initialize orchestrator.

        Args:
            normalized_df: Normalized events DataFrame
            detections: Detections DataFrame
            case_config: Case assembly configuration
            output_dir: Output directory for reports and traces
        """
        self.normalized_df = normalized_df
        self.detections = detections
        self.case_config = case_config
        self.output_dir = Path(output_dir)
        self.trace_file = self.output_dir / "agent_trace.jsonl"

        # Initialize agents
        self.triage_agent = TriageAgent(case_config)
        self.evidence_agent = EvidenceAgent(normalized_df, case_config)
        self.report_agent = ReportAgent(case_config)
        self.critic_agent = CriticAgent(case_config)

    def run(self) -> list[dict[str, Any]]:
        """Run the complete agent orchestration pipeline.

        Returns:
            List of assembled cases
        """
        self._log_trace("orchestrator", "start", {"detection_count": len(self.detections)})

        # Step 1: Triage - group detections into candidate cases
        self._log_trace("triage_agent", "start", {})
        cases = self.triage_agent.group_detections(self.detections)
        self._log_trace("triage_agent", "complete", {"case_count": len(cases)})

        # Step 2: Evidence - retrieve supporting rows for each case
        self._log_trace("evidence_agent", "start", {})
        cases_with_evidence = []
        for case in cases:
            evidence = self.evidence_agent.retrieve_evidence(case)
            case["evidence"] = evidence
            cases_with_evidence.append(case)
        self._log_trace("evidence_agent", "complete", {"cases_processed": len(cases_with_evidence)})

        # Step 3: Critic - validate evidence completeness
        self._log_trace("critic_agent", "start", {})
        validated_cases = []
        for case in cases_with_evidence:
            validation = self.critic_agent.validate_case(case)
            if not validation["is_valid"]:
                # Request additional evidence retrieval
                self._log_trace(
                    "critic_agent", "request_evidence", {"case_id": case.get("case_id")}
                )
                additional_evidence = self.evidence_agent.retrieve_evidence(case, expand=True)
                case["evidence"].extend(additional_evidence)
                # Re-validate
                validation = self.critic_agent.validate_case(case)

            case["validation"] = validation
            validated_cases.append(case)
        self._log_trace("critic_agent", "complete", {"cases_validated": len(validated_cases)})

        # Step 4: Report - generate case reports
        self._log_trace("report_agent", "start", {})
        for case in validated_cases:
            report_content = self.report_agent.generate_report(case)
            case["report_content"] = report_content
        self._log_trace("report_agent", "complete", {"reports_generated": len(validated_cases)})

        # Step 5: Write final case report
        self._write_case_report(validated_cases)

        self._log_trace("orchestrator", "complete", {"final_case_count": len(validated_cases)})

        return validated_cases

    def _log_trace(self, agent: str, step: str, data: dict[str, Any]):
        """Log agent trace step.

        Args:
            agent: Agent name
            step: Step name
            data: Additional data to log
        """
        trace_entry = {
            "agent": agent,
            "step": step,
            "data": data,
        }

        with open(self.trace_file, "a") as f:
            f.write(json.dumps(trace_entry) + "\n")

    def _write_case_report(self, cases: list[dict[str, Any]]):
        """Write consolidated case report to file.

        Args:
            cases: List of validated cases with reports
        """
        report_path = self.output_dir / "case_report.md"

        with open(report_path, "w") as f:
            f.write("# SOC Case Report\n\n")
            f.write(f"**Generated Cases:** {len(cases)}\n\n")
            f.write("---\n\n")

            for i, case in enumerate(cases, 1):
                f.write(f"## Case {i}: {case.get('case_id', f'CASE_{i}')}\n\n")
                f.write(case.get("report_content", "No report content available.\n"))
                f.write("\n---\n\n")

        logger.info(f"Wrote case report to {report_path}")
