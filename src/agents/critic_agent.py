"""Critic agent for validating case completeness with 5-factor confidence model.

Confidence factors:
1. Detection signal strength (from detector confidence)
2. Evidence volume (scaled by min_evidence_rows)
3. Sensor diversity (evidence from multiple sensors)
4. Temporal concentration (evidence clustered near detection)
5. Cross-case correlation (other cases from same source)
"""

import logging
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


class CriticAgent:
    """Validates cases using multi-factor confidence scoring."""

    def __init__(self, config: dict[str, Any]):
        """Initialize critic agent.

        Args:
            config: Case assembly configuration
        """
        self.config = config
        self.min_evidence_rows = config.get("min_evidence_rows", 5)
        self.confidence_threshold = config.get("confidence_threshold", 0.6)
        self._all_cases = []  # Track all cases for cross-case correlation

    def validate_case(self, case: dict[str, Any], all_cases: list[dict] | None = None) -> dict[str, Any]:
        """Validate that a case has sufficient evidence.

        Args:
            case: Case dictionary with evidence
            all_cases: Optional list of all cases for cross-case correlation

        Returns:
            Validation result dictionary with per-factor scores
        """
        if all_cases is not None:
            self._all_cases = all_cases

        evidence = case.get("evidence", [])
        evidence_count = len(evidence)

        # Check minimum evidence requirement
        has_min_evidence = evidence_count >= self.min_evidence_rows

        # Calculate 5-factor confidence
        confidence, factor_scores = self._calculate_confidence(case, evidence)
        meets_threshold = confidence >= self.confidence_threshold

        # Check for evidence references
        has_references = self._check_evidence_references(case)

        is_valid = has_min_evidence and meets_threshold and has_references

        validation = {
            "is_valid": is_valid,
            "confidence": round(confidence, 4),
            "evidence_count": evidence_count,
            "has_min_evidence": has_min_evidence,
            "meets_threshold": meets_threshold,
            "has_references": has_references,
            "factor_scores": factor_scores,
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
            f"valid={is_valid}, confidence={confidence:.2f}, "
            f"factors={factor_scores}"
        )

        return validation

    def _calculate_confidence(self, case: dict[str, Any], evidence: list) -> tuple[float, dict]:
        """Calculate 5-factor confidence score for a case.

        Factors:
        1. Detection signal strength (weight: 0.25) - from detector confidence
        2. Evidence volume (weight: 0.25) - evidence count vs min_evidence_rows
        3. Sensor diversity (weight: 0.20) - evidence from multiple sensors
        4. Temporal concentration (weight: 0.15) - evidence clustered near detection
        5. Cross-case correlation (weight: 0.15) - other cases from same source

        Args:
            case: Case dictionary
            evidence: List of evidence rows

        Returns:
            Tuple of (confidence_score, factor_scores_dict)
        """
        factor_scores = {
            "detection_strength": 0.0,
            "evidence_volume": 0.0,
            "sensor_diversity": 0.0,
            "temporal_concentration": 0.0,
            "cross_case_correlation": 0.0,
        }

        if len(evidence) == 0:
            return 0.0, factor_scores

        # Factor 1: Detection signal strength
        # Use the detector's confidence if available, else fall back to detection count
        detection_confidence = case.get("detection_confidence", 0.0)
        if detection_confidence > 0:
            factor_scores["detection_strength"] = min(1.0, detection_confidence)
        else:
            detection_count = case.get("detection_count", 0)
            factor_scores["detection_strength"] = min(0.7, detection_count / 10.0)

        # Factor 2: Evidence volume
        factor_scores["evidence_volume"] = min(1.0, len(evidence) / self.min_evidence_rows)

        # Factor 3: Sensor diversity
        sensors = set()
        for row in evidence:
            if isinstance(row, dict) and row.get("sensor"):
                sensors.add(row["sensor"])
        if len(sensors) >= 2:
            factor_scores["sensor_diversity"] = 1.0
        elif len(sensors) == 1:
            factor_scores["sensor_diversity"] = 0.5
        else:
            factor_scores["sensor_diversity"] = 0.0

        # Factor 4: Temporal concentration
        timestamps = []
        detection_ts = case.get("ts_start", case.get("ts", 0))
        for row in evidence:
            if isinstance(row, dict) and row.get("ts") is not None:
                try:
                    timestamps.append(float(row["ts"]))
                except (ValueError, TypeError):
                    pass

        if timestamps and detection_ts:
            try:
                detection_ts_float = float(detection_ts)
                diffs = [abs(t - detection_ts_float) for t in timestamps]
                mean_diff = np.mean(diffs)
                # Score: high when evidence is within 5 minutes of detection
                # Decays exponentially with distance
                factor_scores["temporal_concentration"] = float(
                    np.exp(-mean_diff / 300.0)  # 300s = 5 min decay constant
                )
            except (ValueError, TypeError):
                factor_scores["temporal_concentration"] = 0.3

        # Factor 5: Cross-case correlation
        src_ip = case.get("src_ip")
        if src_ip and self._all_cases:
            related_cases = sum(
                1 for c in self._all_cases
                if c.get("src_ip") == src_ip and c.get("case_id") != case.get("case_id")
            )
            factor_scores["cross_case_correlation"] = min(1.0, related_cases / 3.0)

        # Round factor scores
        factor_scores = {k: round(v, 4) for k, v in factor_scores.items()}

        # Weighted combination
        weights = {
            "detection_strength": 0.25,
            "evidence_volume": 0.25,
            "sensor_diversity": 0.20,
            "temporal_concentration": 0.15,
            "cross_case_correlation": 0.15,
        }

        confidence = sum(
            factor_scores[k] * weights[k] for k in weights
        )

        return min(1.0, confidence), factor_scores

    def _check_evidence_references(self, case: dict[str, Any]) -> bool:
        """Check if case has referenceable evidence records.

        Validates that evidence rows contain structured fields that can be
        cited in a report (src_ip, dst_ip, ts, event_type, sensor).

        Args:
            case: Case dictionary

        Returns:
            True if evidence contains referenceable records
        """
        evidence = case.get("evidence", [])
        if len(evidence) == 0:
            return False

        referenceable_fields = {"src_ip", "dst_ip", "ts", "event_type", "sensor"}
        for row in evidence:
            if isinstance(row, dict) and any(
                row.get(field) is not None for field in referenceable_fields
            ):
                return True

        return False
