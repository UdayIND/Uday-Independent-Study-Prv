# SOC-Informed Discovery: Agent-Assisted Threat Detection Pipeline

A reproducible offline pipeline that processes PCAP files through Zeek/Suricata analysis, normalizes events, applies baseline detections, and generates analyst-ready case reports using multi-agent orchestration.

## What It Does

1. **Ingest**: Parses Zeek (`conn.log`, `dns.log`) and Suricata (`eve.json`) logs from PCAP files
2. **Normalize**: Converts heterogeneous logs into unified event schema (Parquet)
3. **Detect**: Applies baseline detectors for recon/scanning and DNS beaconing
4. **Orchestrate**: Multi-agent system (Triage → Evidence → Critic → Report) assembles cases
5. **Report**: Generates markdown case reports with evidence tables and defensive recommendations

## Prerequisites

- Python 3.9+
- Docker & Docker Compose (v2.x) for Zeek/Suricata
- Make

## Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/UdayIND/Uday-Independent-Study-Prv.git
cd Uday-Independent-Study-Prv
make setup

# 2. Download sample PCAP
bash scripts/download_sample_pcap.sh

# 3. Run pipeline
make run PCAP=data/raw/ctu13_neris.pcap

# 4. Verify outputs
make verify
```

## Outputs

Results are written to `reports/runs/<timestamp>/`:

- `events.parquet` - Normalized events DataFrame
- `case_report.md` - Analyst-ready case report (links to evaluation report)
- `run_manifest.json` - Run metadata, PCAP hash, git commit, tool versions
- `agent_trace.jsonl` - Agent orchestration steps (JSONL)
- `detections.jsonl` - Baseline detections
- `evaluation_summary.json` - Evaluation metrics (data health, detection quality, agentic metrics)
- `evaluation_report.md` - Evaluation report with embedded visualizations
- `figures/*.png` - 9 evaluation plots (events per minute, top IPs, protocols, DNS, detections, etc.)

Also generates:
- `data/derived/zeek/conn.log`, `dns.log` (if Docker works)
- `data/derived/suricata/eve.json` (if Docker works)
- `data/normalized/events_<timestamp>.parquet`

### Viewing Evaluation Results

Open `reports/runs/<timestamp>/evaluation_report.md` in a markdown viewer to see:
- Data health metrics (event counts, missing values, top talkers)
- Detection quality metrics (explainability scores, confidence distributions)
- Agentic verification metrics (critic checks, evidence retrieval passes)
- 9 visualizations embedded in the report

## Configuration

Detector thresholds in `configs/detector.yaml`:

```yaml
detectors:
  recon_scanning:
    fan_out_threshold: 50
    burst_threshold: 100
  dns_beaconing:
    repeated_query_threshold: 10
    nxdomain_ratio_threshold: 0.3
```

## Testing

```bash
make test
```

## Evaluation

After running the pipeline, evaluate the most recent run:

```bash
make eval
```

This regenerates evaluation metrics and plots for the latest run directory.

## Troubleshooting

**Zeek/Suricata logs not found**: Ensure Docker is running (`docker info`). Pipeline handles missing logs gracefully.

**No detections**: Lower thresholds in `configs/detector.yaml` for testing.

**PCAP not found**: Place PCAP files in `data/raw/` (gitignored, never committed).

## Multi-Agent Architecture

- **TriageAgent**: Groups detections into cases (IP, time window, detection type)
- **EvidenceAgent**: Retrieves supporting event rows from normalized data
- **CriticAgent**: Validates case completeness and evidence references
- **ReportAgent**: Generates markdown reports with defensive recommendations only

All steps logged to `agent_trace.jsonl` for traceability.

## Security

See [SECURITY.md](SECURITY.md) for defensive-only policy and data handling guidelines.

## License

MIT License - See LICENSE file.
