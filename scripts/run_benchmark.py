#!/usr/bin/env python3
"""Benchmark runner: processes all benchmark PCAPs and compiles comparison.

Reads configs/benchmark.yaml, runs the pipeline for each PCAP, collects
evaluation summaries, and generates a cross-run comparison report.

Usage:
    python scripts/run_benchmark.py
    python scripts/run_benchmark.py --benchmark-config configs/benchmark.yaml
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.eval.metrics import compute_statistical_metrics  # noqa: E402
from src.eval.plots import plot_fp_proxy_comparison  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def load_benchmark_config(config_path: Path) -> dict:
    """Load benchmark configuration."""
    with open(config_path) as f:
        return yaml.safe_load(f)


def find_latest_run_dir(reports_dir: Path) -> Path | None:
    """Find the most recently created run directory."""
    if not reports_dir.exists():
        return None
    run_dirs = sorted(reports_dir.iterdir(), key=lambda p: p.name, reverse=True)
    for d in run_dirs:
        if d.is_dir() and d.name.replace("_", "").isdigit():
            return d
    return None


def run_pipeline_for_pcap(
    pcap_path: Path,
    detector_config_path: Path,
    pcap_label: str,
    expected_sources: list | None = None,
    use_docker: bool = True,
) -> Path | None:
    """Run the full pipeline for a single PCAP.

    Returns the run directory path, or None on failure.
    """
    repo_root = Path(__file__).resolve().parent.parent

    # Clean derived data for fresh run
    derived_zeek = repo_root / "data" / "derived" / "zeek"
    derived_suricata = repo_root / "data" / "derived" / "suricata"
    for d in [derived_zeek, derived_suricata]:
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    abs_pcap = pcap_path.resolve()
    raw_dir = repo_root / "data" / "raw"

    # Compute PCAP path relative to data/raw/ for Docker volume mount
    try:
        pcap_docker_path = str(abs_pcap.relative_to(raw_dir.resolve()))
    except ValueError:
        # PCAP is outside data/raw/, copy it there
        shutil.copy2(str(abs_pcap), str(raw_dir / pcap_path.name))
        pcap_docker_path = pcap_path.name

    if use_docker:
        # Run Zeek
        logger.info(f"  Running Zeek on {pcap_docker_path}...")
        env = os.environ.copy()
        env["PCAP_FILE"] = pcap_docker_path
        try:
            subprocess.run(
                ["docker", "compose", "run", "--rm", "zeek"],
                cwd=str(repo_root),
                env=env,
                capture_output=True,
                timeout=300,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"  Zeek failed: {e}")

        # Run Suricata
        logger.info(f"  Running Suricata on {pcap_docker_path}...")
        try:
            subprocess.run(
                ["docker", "compose", "run", "--rm", "suricata"],
                cwd=str(repo_root),
                env=env,
                capture_output=True,
                timeout=300,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"  Suricata failed: {e}")

    # Run Python pipeline
    logger.info("  Running Python pipeline...")
    cmd = [
        sys.executable,
        "-m",
        "src.main",
        "--pcap",
        str(abs_pcap),
        "--config",
        str(detector_config_path),
        "--pcap-label",
        pcap_label,
    ]
    if expected_sources:
        cmd.extend(["--expected-sources-json", json.dumps(expected_sources)])
    try:
        result = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            logger.error(f"  Pipeline failed: {result.stderr[:500]}")
            return None
    except subprocess.TimeoutExpired:
        logger.error("  Pipeline timed out")
        return None

    # Find the run directory that was just created
    reports_dir = repo_root / "reports" / "runs"
    run_dir = find_latest_run_dir(reports_dir)
    if run_dir is None:
        logger.error("  Could not find run directory")
        return None

    logger.info(f"  Run completed: {run_dir.name}")
    return run_dir


def load_run_summary(run_dir: Path) -> dict | None:
    """Load evaluation summary from a run directory."""
    summary_path = run_dir / "evaluation_summary.json"
    if not summary_path.exists():
        return None
    with open(summary_path) as f:
        return json.load(f)


def generate_benchmark_report(
    results: list[dict], eval_summaries: list[dict], output_dir: Path
) -> None:
    """Generate the benchmark comparison report."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save raw results
    with open(output_dir / "benchmark_summary.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    # Generate FP proxy comparison plot (filter out skipped/failed PCAPs)
    figures_dir = output_dir / "figures"
    figures_dir.mkdir(exist_ok=True)
    active_results = [r for r in results if r.get("status") == "success"]
    plot_fp_proxy_comparison(active_results, figures_dir / "fp_proxy_comparison.png")

    # Compute statistical metrics across successful runs
    stat_metrics = {}
    if eval_summaries:
        stat_metrics = compute_statistical_metrics(eval_summaries)
        with open(output_dir / "statistical_summary.json", "w") as f:
            json.dump(stat_metrics, f, indent=2, default=str)

    # Generate markdown report
    lines = []
    lines.append("# Benchmark Report")
    lines.append("")
    lines.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**PCAPs Processed**: {len(active_results)}/{len(results)}")
    lines.append("")

    # Summary table
    lines.append("## Summary Table")
    lines.append("")
    lines.append(
        "| PCAP | Label | Events | Detections | Cases | Compression | "
        "Evidence Completeness | FP Proxy (det/hr) |"
    )
    lines.append(
        "|------|-------|--------|------------|-------|-------------|"
        "----------------------|--------------------|"
    )

    for r in results:
        fp = r.get("fp_proxy_detections_per_hour")
        fp_str = f"{fp:.2f}" if fp is not None else "N/A"
        ev_comp = r.get("evidence_completeness")
        ev_str = f"{ev_comp:.2%}" if ev_comp is not None else "N/A"
        status = r.get("status", "unknown")
        name = r.get("name", "?")
        if status == "skipped":
            name = f"~~{name}~~ (skipped)"
        lines.append(
            f"| {name} | {r.get('label', '?')} | "
            f"{r.get('total_events', 0)} | {r.get('total_detections', 0)} | "
            f"{r.get('total_cases', 0)} | "
            f"{r.get('compression_ratio', 0.0):.2f} | "
            f"{ev_str} | {fp_str} |"
        )

    lines.append("")

    # Aggregate stats (only from successful runs)
    malicious = [r for r in active_results if r.get("label") == "malicious"]
    benign = [r for r in active_results if r.get("label") == "benign"]

    lines.append("## Aggregate Statistics")
    lines.append("")

    if malicious:
        avg_comp = sum(r.get("compression_ratio", 0) for r in malicious) / len(malicious)
        ev_vals = [
            r.get("evidence_completeness", 0)
            for r in malicious
            if r.get("evidence_completeness") is not None
        ]
        avg_ev = sum(ev_vals) / len(ev_vals) if ev_vals else 0
        avg_det = sum(r.get("total_detections", 0) for r in malicious) / len(malicious)
        lines.append("### Malicious PCAPs")
        lines.append(f"- Average Compression Ratio: {avg_comp:.2f}")
        lines.append(f"- Average Evidence Completeness: {avg_ev:.2%}")
        lines.append(f"- Average Detections: {avg_det:.1f}")
        lines.append("")

    if benign:
        fp_values = [
            r.get("fp_proxy_detections_per_hour", 0)
            for r in benign
            if r.get("fp_proxy_detections_per_hour") is not None
        ]
        avg_fp = sum(fp_values) / len(fp_values) if fp_values else 0
        avg_det_b = sum(r.get("total_detections", 0) for r in benign) / len(benign)
        lines.append("### Benign PCAPs")
        lines.append(f"- Average FP Proxy (detections/hour): {avg_fp:.2f}")
        lines.append(f"- Average Detections: {avg_det_b:.1f}")
        lines.append("")

    # Statistical Summary
    if stat_metrics and stat_metrics.get("n_runs", 0) >= 2:
        lines.append("## Statistical Summary")
        lines.append("")
        lines.append(f"**Runs analyzed**: {stat_metrics.get('n_runs', 0)}")
        lines.append("")
        for metric_name in ["compression_ratio", "evidence_completeness", "fp_proxy", "confidence"]:
            m = stat_metrics.get(metric_name, {})
            if m:
                label = metric_name.replace("_", " ").title()
                lines.append(f"**{label}**:")
                lines.append(f"- Mean: {m.get('mean', 0):.4f} (SD: {m.get('std', 0):.4f})")
                lines.append(f"- 95% CI: [{m.get('ci_lower', 0):.4f}, {m.get('ci_upper', 0):.4f}]")
                lines.append("")
        effect = stat_metrics.get("effect_size")
        if effect:
            g_val = effect.get("hedges_g")
            g_str = f"{g_val:.4f}" if g_val is not None else "N/A (insufficient samples)"
            lines.append(
                f"**Effect Size (Hedge's g)**: {g_str} ({effect.get('interpretation', 'N/A')})"
            )
            lines.append(f"- Malicious detection rate: {effect.get('malicious_mean_rate', 0):.4f}")
            lines.append(f"- Benign detection rate: {effect.get('benign_mean_rate', 0):.4f}")
            if effect.get("n_malicious") is not None:
                lines.append(
                    f"- Samples: n_malicious={effect['n_malicious']}, n_benign={effect['n_benign']}"
                )
            lines.append("")

    # Visualization
    fp_fig = figures_dir / "fp_proxy_comparison.png"
    if fp_fig.exists():
        lines.append("## FP Proxy Comparison")
        lines.append("")
        lines.append("![FP Proxy Comparison](figures/fp_proxy_comparison.png)")
        lines.append("")

    # Per-PCAP details
    lines.append("## Per-PCAP Details")
    lines.append("")
    for r in results:
        lines.append(f"### {r.get('name', '?')} ({r.get('label', '?')})")
        lines.append(f"- Run directory: `{r.get('run_dir', 'N/A')}`")
        lines.append(f"- Total events: {r.get('total_events', 0)}")
        lines.append(f"- Detections: {r.get('total_detections', 0)}")
        lines.append(f"- Cases: {r.get('total_cases', 0)}")
        lines.append("")

    with open(output_dir / "benchmark_report.md", "w") as f:
        f.write("\n".join(lines))

    logger.info(f"Benchmark report saved to {output_dir / 'benchmark_report.md'}")


def main():
    parser = argparse.ArgumentParser(description="Run benchmark suite")
    parser.add_argument(
        "--benchmark-config",
        default="configs/benchmark.yaml",
        help="Benchmark config path",
    )
    parser.add_argument(
        "--detector-config",
        default="configs/detector.yaml",
        help="Detector config path",
    )
    parser.add_argument(
        "--skip-docker",
        action="store_true",
        help="Skip Docker (Zeek/Suricata) processing",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent

    # Load benchmark config
    bm_config_path = repo_root / args.benchmark_config
    if not bm_config_path.exists():
        logger.error(f"Benchmark config not found: {bm_config_path}")
        sys.exit(1)
    bm_config = load_benchmark_config(bm_config_path)

    detector_config_path = repo_root / args.detector_config

    pcaps = bm_config.get("benchmark", {}).get("pcaps", [])
    if not pcaps:
        logger.error("No PCAPs defined in benchmark config")
        sys.exit(1)

    # Apply detector overrides if present
    overrides = bm_config.get("benchmark", {}).get("detector_overrides", {})
    if overrides and detector_config_path.exists():
        with open(detector_config_path) as f:
            det_config = yaml.safe_load(f)
        # Merge overrides
        for detector_name, override_vals in overrides.items():
            if detector_name in det_config.get("detectors", {}):
                det_config["detectors"][detector_name].update(override_vals)
        # Write temporary config
        tmp_config_path = repo_root / "configs" / ".benchmark_detector.yaml"
        with open(tmp_config_path, "w") as f:
            yaml.dump(det_config, f)
        detector_config_path = tmp_config_path

    print("=" * 60)
    print("SOC-Informed Discovery: Benchmark Suite")
    print("=" * 60)
    print(f"PCAPs to process: {len(pcaps)}")
    print("")

    results = []
    eval_summaries = []  # Full evaluation summaries for statistical analysis
    for i, pcap_entry in enumerate(pcaps, 1):
        name = pcap_entry.get("name", f"pcap_{i}")
        pcap_path = repo_root / pcap_entry.get("path", "")
        label = pcap_entry.get("label", "unknown")
        expected_sources = pcap_entry.get("expected_sources", None)

        print(f"[{i}/{len(pcaps)}] Processing: {name} ({label})")

        if not pcap_path.exists():
            logger.warning(f"  PCAP not found: {pcap_path}, skipping")
            results.append(
                {
                    "name": name,
                    "label": label,
                    "status": "skipped",
                    "total_events": 0,
                    "total_detections": 0,
                    "total_cases": 0,
                    "compression_ratio": 0.0,
                    "evidence_completeness": None,
                    "fp_proxy_detections_per_hour": None,
                }
            )
            continue

        run_dir = run_pipeline_for_pcap(
            pcap_path,
            detector_config_path,
            label,
            expected_sources=expected_sources,
            use_docker=not args.skip_docker,
        )

        if run_dir is None:
            logger.error(f"  Pipeline failed for {name}")
            results.append(
                {
                    "name": name,
                    "label": label,
                    "status": "failed",
                    "total_events": 0,
                    "total_detections": 0,
                    "total_cases": 0,
                    "compression_ratio": 0.0,
                    "evidence_completeness": 0.0,
                    "fp_proxy_detections_per_hour": None,
                }
            )
            continue

        # Load evaluation summary
        summary = load_run_summary(run_dir)
        if summary is None:
            logger.warning(f"  No evaluation summary for {name}")
            continue

        soc = summary.get("soc_metrics", {})
        dh = summary.get("data_health", {})
        dq = summary.get("detection_quality", {})

        eval_summaries.append(summary)

        result = {
            "name": name,
            "label": label,
            "status": "success",
            "run_dir": str(run_dir),
            "total_events": dh.get("total_events", 0),
            "total_detections": dq.get("total_detections", 0),
            "total_cases": soc.get("assembled_cases", 0),
            "compression_ratio": soc.get("compression_ratio", 0.0),
            "evidence_completeness": soc.get("evidence_completeness"),
            "fp_proxy_detections_per_hour": soc.get("fp_proxy_detections_per_hour"),
        }
        results.append(result)
        print(
            f"  Events: {result['total_events']}, "
            f"Detections: {result['total_detections']}, "
            f"Cases: {result['total_cases']}"
        )
        print("")

    # Generate benchmark report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = repo_root / "reports" / "benchmark" / timestamp
    generate_benchmark_report(results, eval_summaries, output_dir)

    # Clean up temporary config
    tmp_config = repo_root / "configs" / ".benchmark_detector.yaml"
    if tmp_config.exists():
        tmp_config.unlink()

    print("")
    print("=" * 60)
    print(f"Benchmark complete: {output_dir}")
    print("=" * 60)

    # Print summary table
    successful = [r for r in results if r.get("status") == "success"]
    print(f"\nSuccessful: {len(successful)}/{len(results)}")
    for r in successful:
        print(
            f"  {r['name']}: {r['total_detections']} detections, "
            f"{r['total_cases']} cases, "
            f"compression={r['compression_ratio']:.2f}"
        )


if __name__ == "__main__":
    main()
