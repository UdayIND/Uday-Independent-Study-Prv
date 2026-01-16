#!/usr/bin/env python3
"""Detector tuning script that iterates over threshold presets to find working configuration."""

import argparse
import logging
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# Threshold presets (from conservative to permissive)
PRESETS = [
    {
        "name": "conservative",
        "recon_scanning": {
            "fan_out_threshold": 50,
            "burst_threshold": 100,
        },
        "dns_beaconing": {
            "repeated_query_threshold": 10,
            "nxdomain_ratio_threshold": 0.3,
        },
    },
    {
        "name": "moderate",
        "recon_scanning": {
            "fan_out_threshold": 20,
            "burst_threshold": 50,
        },
        "dns_beaconing": {
            "repeated_query_threshold": 5,
            "nxdomain_ratio_threshold": 0.15,
        },
    },
    {
        "name": "permissive",
        "recon_scanning": {
            "fan_out_threshold": 10,
            "burst_threshold": 20,
        },
        "dns_beaconing": {
            "repeated_query_threshold": 3,
            "nxdomain_ratio_threshold": 0.1,
        },
    },
    {
        "name": "very_permissive",
        "recon_scanning": {
            "fan_out_threshold": 5,
            "burst_threshold": 10,
        },
        "dns_beaconing": {
            "repeated_query_threshold": 2,
            "nxdomain_ratio_threshold": 0.05,
        },
    },
]


def load_config(config_path: Path) -> dict:
    """Load detector configuration."""
    with open(config_path) as f:
        return yaml.safe_load(f)


def save_config(config: dict, config_path: Path) -> None:
    """Save detector configuration."""
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def apply_preset(config: dict, preset: dict) -> dict:
    """Apply threshold preset to configuration."""
    config_copy = config.copy()
    if "recon_scanning" in config_copy.get("detectors", {}):
        config_copy["detectors"]["recon_scanning"].update(preset["recon_scanning"])
    if "dns_beaconing" in config_copy.get("detectors", {}):
        config_copy["detectors"]["dns_beaconing"].update(preset["dns_beaconing"])
    return config_copy


def count_detections(detections_path: Path) -> int:
    """Count detections in JSONL file."""
    if not detections_path.exists():
        return 0
    count = 0
    with open(detections_path) as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def find_latest_run() -> Path | None:
    """Find the latest run directory."""
    runs_dir = Path("reports/runs")
    if not runs_dir.exists():
        return None
    run_dirs = sorted(runs_dir.iterdir(), key=lambda p: p.name, reverse=True)
    return run_dirs[0] if run_dirs else None


def main():
    """Main tuning function."""
    parser = argparse.ArgumentParser(description="Tune detector thresholds to find detections")
    parser.add_argument("--pcap", type=str, required=True, help="Path to PCAP file")
    parser.add_argument(
        "--config", type=str, default="configs/detector.yaml", help="Path to detector config"
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

    # Backup original config
    backup_path = config_path.with_suffix(".yaml.backup")
    logger.info(f"Backing up original config to {backup_path}")
    shutil.copy(config_path, backup_path)

    try:
        original_config = load_config(config_path)
        best_preset = None
        best_detections = 0
        best_run_dir = None

        logger.info("Starting detector tuning...")
        logger.info(f"Testing {len(PRESETS)} threshold presets")

        for preset in PRESETS:
            logger.info(f"\n--- Testing preset: {preset['name']} ---")
            logger.info(
                f"  Recon: fan_out={preset['recon_scanning']['fan_out_threshold']}, "
                f"burst={preset['recon_scanning']['burst_threshold']}"
            )
            logger.info(
                f"  DNS: repeated={preset['dns_beaconing']['repeated_query_threshold']}, "
                f"nxdomain={preset['dns_beaconing']['nxdomain_ratio_threshold']}"
            )

            # Apply preset
            test_config = apply_preset(original_config, preset)
            save_config(test_config, config_path)

            # Run pipeline
            logger.info("Running pipeline...")
            try:
                result = subprocess.run(
                    ["make", "run", f"PCAP={pcap_path}"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != 0:
                    logger.warning(f"Pipeline returned non-zero exit code: {result.returncode}")
                    logger.debug(result.stderr)
                    continue
            except Exception as e:
                logger.error(f"Error running pipeline: {e}")
                continue

            # Check detections
            latest_run = find_latest_run()
            if latest_run:
                detections_path = latest_run / "detections.jsonl"
                detection_count = count_detections(detections_path)
                logger.info(f"Found {detection_count} detections with preset '{preset['name']}'")

                if detection_count > best_detections:
                    best_detections = detection_count
                    best_preset = preset
                    best_run_dir = latest_run
                elif best_run_dir is None:
                    # Track first run even if no detections
                    best_run_dir = latest_run
                    best_preset = preset

                # Stop if we found detections
                if detection_count > 0:
                    logger.info(
                        f"\n✓ Success! Found {detection_count} detections with preset '{preset['name']}'"
                    )
                    break
            else:
                logger.warning("No run directory found after pipeline execution")
                # Still track this as a potential best run if we don't have one
                if best_run_dir is None:
                    best_run_dir = latest_run

        # Restore original config
        logger.info("\nRestoring original configuration...")
        shutil.copy(backup_path, config_path)

        # Generate tuning results report
        if best_run_dir:
            generate_tuning_results(best_preset, best_detections, best_run_dir, PRESETS)

        if best_detections > 0:
            logger.info(
                f"\n✓ Tuning complete! Best preset: '{best_preset['name']}' with {best_detections} detections"
            )
            logger.info(f"Results saved to: {best_run_dir}/tuning_results.md")
            sys.exit(0)
        else:
            logger.warning(
                "\n⚠ No detections found with any preset. Check no_detections_diagnosis.md for analysis."
            )
            sys.exit(1)

    except KeyboardInterrupt:
        logger.info("\nTuning interrupted by user")
        shutil.copy(backup_path, config_path)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during tuning: {e}", exc_info=True)
        shutil.copy(backup_path, config_path)
        sys.exit(1)


def generate_tuning_results(
    best_preset: dict, best_detections: int, run_dir: Path, all_presets: list[dict]
) -> None:
    """Generate tuning results markdown report."""
    lines = []
    lines.append("# Detector Tuning Results")
    lines.append("")
    if best_detections > 0:
        lines.append(f"**Best Preset**: {best_preset['name']}")
        lines.append(f"**Detections Found**: {best_detections}")
    else:
        lines.append("**Result**: No detections found with any preset")
        lines.append(f"**Last Preset Tested**: {best_preset['name']}")
        lines.append("")
        lines.append(
            "**Recommendation**: Check `no_detections_diagnosis.md` for detailed analysis."
        )
        lines.append("Possible reasons:")
        lines.append("- No events parsed from PCAP (check Zeek/Suricata logs)")
        lines.append("- Traffic patterns don't match detector criteria")
        lines.append("- Thresholds may need to be even more permissive")
    lines.append("")

    lines.append("## Best Configuration")
    lines.append("")
    lines.append("```yaml")
    lines.append("detectors:")
    lines.append("  recon_scanning:")
    for key, value in best_preset["recon_scanning"].items():
        lines.append(f"    {key}: {value}")
    lines.append("  dns_beaconing:")
    for key, value in best_preset["dns_beaconing"].items():
        lines.append(f"    {key}: {value}")
    lines.append("```")
    lines.append("")

    lines.append("## All Presets Tested")
    lines.append("")
    lines.append("| Preset | Fan-out | Burst | Repeated | NXDOMAIN | Detections |")
    lines.append("|--------|---------|-------|----------|----------|------------|")
    for preset in all_presets:
        marker = "✓" if preset == best_preset else ""
        lines.append(
            f"| {preset['name']}{marker} | "
            f"{preset['recon_scanning']['fan_out_threshold']} | "
            f"{preset['recon_scanning']['burst_threshold']} | "
            f"{preset['dns_beaconing']['repeated_query_threshold']} | "
            f"{preset['dns_beaconing']['nxdomain_ratio_threshold']:.2f} | "
            f"{best_detections if preset == best_preset else 'N/A'} |"
        )
    lines.append("")

    lines.append("## Apply Best Configuration")
    lines.append("")
    lines.append("To use the best configuration, update `configs/detector.yaml` with:")
    lines.append("")
    lines.append("```yaml")
    lines.append("detectors:")
    lines.append("  recon_scanning:")
    for key, value in best_preset["recon_scanning"].items():
        lines.append(f"    {key}: {value}")
    lines.append("  dns_beaconing:")
    for key, value in best_preset["dns_beaconing"].items():
        lines.append(f"    {key}: {value}")
    lines.append("```")
    lines.append("")

    output_path = run_dir / "tuning_results.md"
    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    logger.info(f"Saved tuning results to {output_path}")


if __name__ == "__main__":
    main()
