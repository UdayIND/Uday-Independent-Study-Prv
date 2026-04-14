#!/usr/bin/env python3
"""Standalone evaluation runner for a single run directory.

Usage:
    python scripts/run_eval.py --run-dir reports/runs/20260115_195715 --config configs/detector.yaml
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import pandas as pd
import yaml

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.eval.evaluator import Evaluator  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Re-evaluate a pipeline run")
    parser.add_argument("--run-dir", required=True, help="Path to run directory")
    parser.add_argument(
        "--config", default="configs/detector.yaml", help="Detector config path"
    )
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        logger.error(f"Run directory not found: {run_dir}")
        sys.exit(1)

    # Load config
    config_path = Path(args.config)
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
    else:
        logger.warning(f"Config not found at {config_path}, using defaults")
        config = {}

    # Load events
    events_path = run_dir / "events.parquet"
    if events_path.exists():
        events_df = pd.read_parquet(events_path)
        logger.info(f"Loaded {len(events_df)} events from {events_path}")
    else:
        logger.error(f"Events file not found: {events_path}")
        sys.exit(1)

    # Load detections
    detections = []
    detections_path = run_dir / "detections.jsonl"
    if detections_path.exists():
        with open(detections_path) as f:
            for line in f:
                if line.strip():
                    detections.append(json.loads(line))
    logger.info(f"Loaded {len(detections)} detections")

    # Load cases
    cases = []
    cases_path = run_dir / "cases.json"
    if cases_path.exists():
        with open(cases_path) as f:
            cases = json.load(f)
        logger.info(f"Loaded {len(cases)} cases from {cases_path}")
    else:
        logger.warning("No cases.json found, using empty cases list")

    # Run evaluation
    evaluator = Evaluator(run_dir, config)
    summary = evaluator.evaluate(events_df, detections, cases)

    # Print summary
    soc = summary.get("soc_metrics", {})
    dq = summary.get("detection_quality", {})
    dh = summary.get("data_health", {})
    print("\n" + "=" * 50)
    print("Evaluation Summary")
    print("=" * 50)
    print(f"  Total Events:           {dh.get('total_events', 0)}")
    print(f"  Total Detections:       {dq.get('total_detections', 0)}")
    print(f"  Compression Ratio:      {soc.get('compression_ratio', 0.0):.2f}")
    print(f"  Evidence Completeness:  {soc.get('evidence_completeness', 0.0):.2%}")
    fp = soc.get("fp_proxy_detections_per_hour")
    if fp is not None:
        print(f"  FP Proxy (det/hour):    {fp:.2f}")
    print(f"  Explainability Score:   {dq.get('explainability_score', 0.0):.2%}")
    print("=" * 50)


if __name__ == "__main__":
    main()
