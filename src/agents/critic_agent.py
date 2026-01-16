"""Critic agent for validating case completeness."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class CriticAgent:
    """Validates that cases have sufficient evidence."""

    def __init__(self, config: dict[str, Any]):
        """Initialize critic agent.

        Args:
            config: Case assembly configuration
        """
        self.config = config
        self.min_evidence_rows = config.get("min_evidence_rows", 5)
        self.confidence_threshold = config.get("confidence_threshold", 0.6)

    def validate_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Validate that a case has sufficient evidence.

        Args:
            case: Case dictionary with evidence

        Returns:
            Validation result dictionary
        """
        evidence = case.get("evidence", [])
        evidence_count = len(evidence)

        # Check minimum evidence requirement
        has_min_evidence = evidence_count >= self.min_evidence_rows

        # Calculate confidence based on evidence quality
        confidence = self._calculate_confidence(case, evidence)
        meets_threshold = confidence >= self.confidence_threshold

        # Check for evidence references
        has_references = self._check_evidence_references(case)

        is_valid = has_min_evidence and meets_threshold and has_references

        validation = {
            "is_valid": is_valid,
            "confidence": confidence,
            "evidence_count": evidence_count,
            "has_min_evidence": has_min_evidence,
            "meets_threshold": meets_threshold,
            "has_references": has_references,
            "issues": [],
        }

        if not has_min_evidence:
            validation["issues"].append(
                f"Insufficient evidence rows: {evidence_count} < {self.min_evidence_rows}"
            )

        if not meets_threshold:
            validation["issues"].append(
                f"Confidence too low: {confidence:.2f} < {self.confidence_threshold}"
            )

        if not has_references:
            validation["issues"].append("Missing evidence references in report")

        logger.info(
            f"Critic agent validated case {case.get('case_id')}: "
            f"valid={is_valid}, confidence={confidence:.2f}"
        )

        return validation

    def _calculate_confidence(self, case: dict[str, Any], evidence: list) -> float:
        """Calculate confidence score for a case.

        Args:
            case: Case dictionary
            evidence: List of evidence rows

        Returns:
            Confidence score between 0 and 1
        """
        if len(evidence) == 0:
            return 0.0

        # Base confidence from detection count
        detection_count = case.get("detection_count", 0)
        base_confidence = min(0.7, detection_count / 10.0)

        # Evidence quality factor
        evidence_factor = min(1.0, len(evidence) / self.min_evidence_rows)

        # Combine factors
        confidence = base_confidence * 0.5 + evidence_factor * 0.5

        return min(1.0, confidence)

    def _check_evidence_references(self, case: dict[str, Any]) -> bool:
        """Check if case report has evidence references.

        Args:
            case: Case dictionary

        Returns:
            True if evidence references are present
        """
        # Check if evidence exists
        evidence = case.get("evidence", [])
        if len(evidence) == 0:
            return False

        # Check if report content mentions evidence
        report_content = case.get("report_content", "")
        if "Evidence" in report_content or "evidence" in report_content:
            return True

        return False
