"""Triage agent for grouping detections into candidate cases.

Dual-mode operation:
- Heuristic grouping: Groups raw detections into candidate cases by source IP,
  detection type, and time window (always available, used by orchestrator)
- LLM narrative synthesis (optional): Converts PPO policy output into analyst-readable
  narratives for the SENTINEL-RL orchestration plane (Section IV-D). Requires OPENAI_API_KEY.
"""

import logging
from datetime import timedelta
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


class TriageAgent:
    """Groups raw detections into candidate cases and optionally synthesizes LLM narratives."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize triage agent.

        Args:
            config: Case assembly configuration. If None, uses defaults.
        """
        if config is None:
            config = {}
        self.config = config
        self.time_window = timedelta(seconds=config.get("time_window_seconds", 1800))
        self._llm_chain = None  # Lazy-loaded LLM chain

    # ================================================================
    # Heuristic grouping (always available, used by orchestrator)
    # ================================================================

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
        window_seconds = int(self.time_window.total_seconds())
        epoch_seconds = detections["ts_dt"].astype("int64") // 10**9
        detections["time_bucket"] = epoch_seconds // window_seconds

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

            # Propagate detection metadata and confidence to case level
            if "metadata" in group.columns:
                first_meta = group.iloc[0].get("metadata")
                if isinstance(first_meta, dict):
                    case["metadata"] = first_meta
            if "confidence" in group.columns:
                case["detection_confidence"] = float(group["confidence"].max())

            cases.append(case)
            case_id += 1

        logger.info(f"Triage agent grouped {len(detections)} detections into {len(cases)} cases")
        return cases

    # ================================================================
    # LLM narrative synthesis (SENTINEL-RL Orchestration Plane)
    # Section IV-D: Converts PPO policy output into analyst narratives
    # ================================================================

    def _get_llm_chain(self):
        """Lazy-load the LangChain narrative synthesis chain."""
        if self._llm_chain is not None:
            return self._llm_chain

        try:
            from langchain.chains import LLMChain
            from langchain.prompts import PromptTemplate
            from langchain_openai import ChatOpenAI

            from src.config import Config

            if not Config.OPENAI_API_KEY:
                return None

            llm = ChatOpenAI(
                api_key=Config.OPENAI_API_KEY,
                model="gpt-4o-mini",
                temperature=0.1,
            )
            prompt = PromptTemplate(
                input_variables=["src_ip", "action_name", "state_norm"],
                template=(
                    "You are an expert Security Operations Center (SOC) Triage Analyst.\n"
                    "The SENTINEL-RL PPO Agent has recommended the following action based "
                    "on the Neo4j authentication graph:\n"
                    "- Suspicious Host IP: {src_ip}\n"
                    "- Recommended Action: {action_name}\n"
                    "- Graph State Density (Norm): {state_norm}\n\n"
                    "Draft a clear, concise, 2-sentence narrative explanation for a human "
                    "analyst explaining why this action makes sense given the context of "
                    "lateral movement and credential abuse. Do NOT hallucinate evidence."
                ),
            )
            self._llm_chain = LLMChain(llm=llm, prompt=prompt)
            return self._llm_chain
        except ImportError:
            logger.warning("LangChain not available. LLM narrative synthesis disabled.")
            return None

    def synthesize_narrative(self, ppo_output: dict[str, Any]) -> str:
        """Synthesize an analyst-readable narrative from PPO policy output.

        Args:
            ppo_output: Output from the PPO inference containing action_name,
                       src_ip, and metrics.

        Returns:
            Narrative string for the analyst workbench.
        """
        chain = self._get_llm_chain()
        if chain is None:
            action = ppo_output.get("action_name", "Unknown")
            src_ip = ppo_output.get("src_ip", "Unknown")
            return f"[LLM Disabled] PPO recommends: {action} on {src_ip}."

        try:
            response = chain.run(
                src_ip=ppo_output.get("src_ip", "Unknown"),
                action_name=ppo_output.get("action_name", "Unknown"),
                state_norm=round(ppo_output.get("metrics", {}).get("state_norm", 0.0), 3),
            )
            return response.strip()
        except Exception as e:
            logger.error(f"Triage LLM synthesis failed: {e}")
            return f"Error generating narrative: {ppo_output.get('action_name')}"
