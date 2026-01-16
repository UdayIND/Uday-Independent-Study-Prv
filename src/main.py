#!/usr/bin/env python3
"""Main entry point for the SOC-Informed Discovery pipeline."""

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import yaml

from src.agents.orchestrator import AgentOrchestrator  # noqa: E402
from src.detect_baseline.detector import BaselineDetector  # noqa: E402
from src.eval.evaluator import Evaluator  # noqa: E402
from src.ingest.suricata_parser import SuricataParser  # noqa: E402
from src.ingest.zeek_parser import ZeekParser  # noqa: E402
from src.normalize.normalizer import EventNormalizer  # noqa: E402
from src.report.manifest import ManifestGenerator  # noqa: E402

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def get_git_info() -> dict:
    """Get current git commit hash and branch."""
    try:
        commit_hash = (
            subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
            .decode()
            .strip()
        )
        branch = (
            subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
        return {"commit": commit_hash, "branch": branch}
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {"commit": "unknown", "branch": "unknown"}


def load_config(config_path: Path) -> dict:
    """Load detector configuration."""
    with open(config_path) as f:
        return yaml.safe_load(f)


def run_pipeline(pcap_path: Path, config_path: Path, output_dir: Path) -> None:
    """Execute the complete pipeline."""
    logger.info(f"Starting pipeline for PCAP: {pcap_path}")

    # Create output directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    # Load configuration
    config = load_config(config_path)
    detector_config = config.get("detectors", {})
    case_config = config.get("case_assembly", {})

    # Step 1: Parse Zeek logs
    logger.info("Parsing Zeek logs...")
    zeek_dir = Path("data/derived/zeek")
    zeek_parser = ZeekParser(zeek_dir)
    zeek_events = zeek_parser.parse_all()
    logger.info(f"Parsed {len(zeek_events)} Zeek events")

    # Step 2: Parse Suricata logs
    logger.info("Parsing Suricata logs...")
    suricata_dir = Path("data/derived/suricata")
    suricata_parser = SuricataParser(suricata_dir)
    suricata_events = suricata_parser.parse_all()
    logger.info(f"Parsed {len(suricata_events)} Suricata events")

    # Step 3: Normalize events
    logger.info("Normalizing events...")
    normalizer = EventNormalizer()
    normalized_df = normalizer.normalize(zeek_events, suricata_events)

    # Save normalized events to both run directory and data/normalized
    normalized_path_run = run_dir / "events.parquet"
    normalized_path_data = Path("data/normalized") / f"events_{timestamp}.parquet"
    Path("data/normalized").mkdir(parents=True, exist_ok=True)

    normalized_df.to_parquet(normalized_path_run, index=False)
    normalized_df.to_parquet(normalized_path_data, index=False)
    logger.info(
        f"Saved {len(normalized_df)} normalized events to {normalized_path_run} and {normalized_path_data}"
    )

    # Step 4: Baseline detection
    logger.info("Running baseline detectors...")
    detector = BaselineDetector(detector_config)
    detections = detector.detect(normalized_df)
    logger.info(f"Generated {len(detections)} detections")

    # Convert detections DataFrame to list of dicts for evaluation
    detections_list = []
    if len(detections) > 0:
        detections_list = detections.to_dict("records")

    # Save detections to JSONL
    detections_path = run_dir / "detections.jsonl"
    if len(detections_list) > 0:
        with open(detections_path, "w") as f:
            for det in detections_list:
                f.write(json.dumps(det) + "\n")
        logger.info(f"Saved {len(detections_list)} detections to {detections_path}")
    else:
        # Create empty file
        detections_path.touch()
        logger.info("No detections found, created empty detections.jsonl")

    # Step 5: Agent orchestration
    logger.info("Running agent orchestration...")
    orchestrator = AgentOrchestrator(
        normalized_df=normalized_df,
        detections=detections,
        case_config=case_config,
        output_dir=run_dir,
    )
    cases = orchestrator.run()
    logger.info(f"Generated {len(cases)} cases")

    # Step 5.5: Evaluation
    logger.info("Running evaluation...")
    evaluator = Evaluator(run_dir, config)
    evaluator.evaluate(normalized_df, detections_list, cases)
    logger.info("Evaluation completed")

    # Step 6: Generate manifest
    logger.info("Generating run manifest...")
    git_info = get_git_info()
    manifest_gen = ManifestGenerator(
        pcap_path=pcap_path,
        run_dir=run_dir,
        git_info=git_info,
        config=config,
    )
    manifest = manifest_gen.generate()

    manifest_path = run_dir / "run_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"Saved manifest to {manifest_path}")

    logger.info("Pipeline completed successfully!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SOC-Informed Discovery: Agent-Assisted Threat Detection Pipeline"
    )
    parser.add_argument(
        "--pcap",
        type=str,
        required=True,
        help="Path to PCAP file",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="configs/detector.yaml",
        help="Path to detector configuration file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="reports/runs",
        help="Output directory for reports",
    )

    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {pcap_path}")
        sys.exit(1)

    config_path = Path(args.config)
    if not config_path.exists():
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        run_pipeline(pcap_path, config_path, output_dir)
    except Exception as e:
        logger.error(f"Pipeline failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
