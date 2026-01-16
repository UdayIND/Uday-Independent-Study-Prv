# SOC-Informed Discovery: Agent-Assisted Threat Detection Pipeline

**Agent-Assisted Threat Detection from Public Cybersecurity Telemetry (SOC-Informed Discovery)**

A fully reproducible offline pipeline for analyzing PCAP files and generating analyst-ready threat detection reports using multi-agent orchestration.

## 🎯 Overview

This pipeline processes network PCAP files through a multi-stage analysis workflow:

1. **Ingest**: Parse Zeek and Suricata logs from PCAP analysis
2. **Normalize**: Convert heterogeneous log formats into unified event schema
3. **Detect**: Apply baseline detection algorithms (recon/scanning, DNS beaconing)
4. **Orchestrate**: Multi-agent system for case assembly and evidence gathering
5. **Report**: Generate analyst-ready case reports with defensive recommendations

## 📋 Prerequisites

- **Python**: 3.9 or higher
- **Docker & Docker Compose**: For running Zeek and Suricata services (v2.x)
- **Make**: For running pipeline commands
- **Git**: For version control and manifest generation

### Optional (for local development)
- Zeek (if running without Docker)
- Suricata (if running without Docker)

**Note**: Docker must be running for PCAP processing. If Docker is not available, the pipeline will still execute but requires pre-generated log files.

## 🚀 Quick Start

### 1. Setup

```bash
# Clone the repository
git clone https://github.com/UdayIND/Uday-Independent-Study-Prv.git
cd Uday-Independent-Study-Prv

# Run preflight checks
make preflight

# Install dependencies
make setup
```

### 2. Prepare PCAP File

**Option A: Download a sample PCAP**
```bash
# Small sample for quick testing
bash scripts/download_tiny_pcap.sh

# Or larger sample
bash scripts/download_sample_pcap.sh
```

**Option B: Use your own PCAP**
```bash
cp /path/to/your/capture.pcap data/raw/
```

### 3. Run Pipeline

```bash
# Using Makefile
make run PCAP=data/raw/capture.pcap

# Or directly with Python
python -m src.main --pcap data/raw/capture.pcap
```

### 4. View Results

Results are written to `reports/runs/<timestamp>/`:
- `events.parquet`: Normalized events DataFrame
- `case_report.md`: Analyst-ready case report
- `run_manifest.json`: Run metadata, hashes, tool versions
- `agent_trace.jsonl`: Agent orchestration trace

## 📁 Repository Structure

```
.
├── data/
│   ├── raw/              # Input PCAP files (gitignored)
│   ├── derived/
│   │   ├── zeek/         # Zeek log outputs
│   │   └── suricata/     # Suricata eve.json outputs
│   └── normalized/       # Normalized event parquet files
├── reports/
│   └── runs/             # Timestamped run outputs
├── src/
│   ├── ingest/           # Zeek/Suricata parsers
│   ├── normalize/        # Event normalization
│   ├── features/         # Feature extraction
│   ├── detect_baseline/  # Baseline detectors
│   ├── report/           # Report generation
│   └── agents/           # Multi-agent orchestration
├── configs/              # Detector and tool configurations
├── tests/                # Pytest test suite
├── scripts/              # Utility scripts
└── docs/                 # Project documentation
```

## 🐳 Docker Usage

The pipeline can run entirely in Docker:

```bash
# Build images
make docker-build

# Run with Docker Compose (set PCAP_FILE environment variable)
PCAP_FILE=capture.pcap docker-compose up

# Or use the Makefile wrapper
PCAP_FILE=capture.pcap make docker-up
```

## 🔧 Configuration

Detector thresholds and time windows are configured in `configs/detector.yaml`:

```yaml
detectors:
  recon_scanning:
    enabled: true
    time_window_seconds: 300
    fan_out_threshold: 50
    burst_threshold: 100

  dns_beaconing:
    enabled: true
    time_window_seconds: 600
    repeated_query_threshold: 10
    nxdomain_ratio_threshold: 0.3
```

## 🧪 Testing

Run the test suite:

```bash
make test
```

Run specific tests:

```bash
pytest tests/test_normalizer.py -v
```

## 📊 Pipeline Outputs

### 1. Zeek Logs (`data/derived/zeek/`)
- `conn.log`: Connection events (JSON format)
- `dns.log`: DNS query/response events

### 2. Suricata Logs (`data/derived/suricata/`)
- `eve.json`: Unified event log with alerts, flows, DNS, HTTP

### 3. Normalized Events (`reports/runs/<timestamp>/events.parquet`)
Unified schema with fields:
- `ts`, `sensor`, `event_type`, `src_ip`, `dst_ip`, `src_port`, `dst_port`
- `proto`, `uid`, `flow_id`, `severity`, `signature`, `metadata`, `case_id`

### 4. Baseline Detections
- **Recon/Scanning**: High fan-out connections, bursty traffic patterns
- **DNS Beaconing**: Repeated queries, periodic patterns, NXDOMAIN ratios

### 5. Case Report (`case_report.md`)
- Executive summary per case
- Timeline of events
- Evidence table with supporting rows
- Confidence scores and limitations
- Defensive action recommendations

### 6. Run Manifest (`run_manifest.json`)
- PCAP file hash (SHA256)
- Git commit and branch
- Tool versions (Python, Zeek, Suricata)
- Configuration snapshot
- Output file hashes

### 7. Agent Trace (`agent_trace.jsonl`)
JSONL file with agent orchestration steps:
- Triage agent: Detection grouping
- Evidence agent: Evidence retrieval
- Critic agent: Validation and feedback
- Report agent: Report generation

## 🤖 Multi-Agent Architecture

The pipeline uses a deterministic multi-agent orchestration system:

1. **TriageAgent**: Groups raw detections into candidate cases based on IP, time windows, and detection type
2. **EvidenceAgent**: Retrieves supporting event rows from normalized data for each case
3. **CriticAgent**: Validates case completeness and requests additional evidence if needed
4. **ReportAgent**: Generates markdown case reports with evidence tables and recommendations

All agent steps are logged to `agent_trace.jsonl` for full traceability.

## 🛠️ Development

### Code Formatting

```bash
make format    # Format with black
make lint      # Run ruff and mypy
```

### Pre-commit Hooks

Pre-commit hooks are installed automatically with `make setup`. They check:
- Trailing whitespace
- File endings
- YAML/JSON validity
- Code formatting (black)
- Linting (ruff)

## 🔍 Troubleshooting

### Issue: Zeek/Suricata logs not found

**Solution**:
1. Ensure Docker is running: `docker info`
2. Check Docker containers ran successfully:
```bash
docker compose logs zeek
docker compose logs suricata
```
3. If Docker is not available, manually place log files in `data/derived/zeek/` and `data/derived/suricata/`

### Issue: No detections generated

**Solution**: Check detector thresholds in `configs/detector.yaml`. Lower thresholds for testing:
```yaml
recon_scanning:
  fan_out_threshold: 10  # Lower for testing
```

### Issue: Agent trace file empty

**Solution**: Check file permissions and ensure output directory exists:
```bash
mkdir -p reports/runs
chmod -R 755 reports/
```

### Issue: Parquet file read errors

**Solution**: Ensure pyarrow is installed:
```bash
pip install pyarrow>=12.0.0
```

## 📚 Documentation

- [Project Brief](docs/PROJECT_BRIEF.md): Executive summary, motivation, approach, progress
- [Project Charter](docs/PROJECT_CHARTER.md): Project scope, objectives, deliverables
- [Data Plan](docs/DATA_PLAN.md): Data sources, schemas, processing workflows
- [SOC Ask/Offer Memo](docs/SOC_ASK_OFFER_MEMO.md): SOC team collaboration proposal

## 🔒 Security

See [SECURITY.md](SECURITY.md) for security guidelines and defensive-only recommendations.

## 📝 License

MIT License - See LICENSE file for details.

## 👤 Author

Uday - Independent Study Project

## 🙏 Acknowledgments

- Zeek Project: Network analysis framework
- Suricata: Intrusion detection system
- Python Security Community: Best practices and tooling
