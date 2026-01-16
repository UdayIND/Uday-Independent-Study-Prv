# Quick Start Guide

## Prerequisites Check

```bash
# Check Python version (3.9+ required)
python3 --version

# Check Docker (required for Zeek/Suricata processing)
docker --version
docker compose version

# Check Make
make --version

# Note: If Docker is not running, the pipeline will still execute but will skip
# Zeek and Suricata processing. You'll need existing log files for analysis.
```

## Initial Setup

```bash
# 1. Install dependencies
make setup

# 2. Verify installation
python3 -m pytest tests/ -v
```

## Running the Pipeline

### Option 1: Using Makefile (Recommended)

```bash
# Download a sample PCAP (optional)
bash scripts/download_tiny_pcap.sh

# Or place your PCAP file in data/raw/
cp /path/to/capture.pcap data/raw/

# Run pipeline (requires Docker for Zeek/Suricata)
make run PCAP=data/raw/capture.pcap

# Verify outputs
make verify
```

**Note**: Docker must be running for Zeek and Suricata processing. If Docker is not available, the pipeline will still run but will only process existing log files.

### Option 2: Using Python Directly

```bash
python3 -m src.main --pcap data/raw/capture.pcap
```

### Option 3: Using Docker Compose

```bash
# Set PCAP file name
export PCAP_FILE=capture.pcap

# Copy PCAP to data/raw/
cp /path/to/capture.pcap data/raw/

# Run with Docker Compose
docker-compose up
```

## Viewing Results

Results are in `reports/runs/<timestamp>/`:

```bash
# List recent runs
ls -lt reports/runs/ | head -5

# View case report
cat reports/runs/<timestamp>/case_report.md

# View manifest
cat reports/runs/<timestamp>/run_manifest.json | jq

# View agent trace
cat reports/runs/<timestamp>/agent_trace.jsonl | jq
```

## Common Tasks

### Run Tests

```bash
make test
```

### Format Code

```bash
make format
```

### Lint Code

```bash
make lint
```

### Clean Generated Files

```bash
make clean
```

## Troubleshooting

### Issue: "PCAP file not found"

**Solution**: Ensure PCAP file is in `data/raw/` directory:
```bash
ls -lh data/raw/
```

### Issue: "Docker daemon not running"

**Solution**: Start Docker Desktop or Docker daemon:
```bash
# macOS: Start Docker Desktop application
# Linux: sudo systemctl start docker

# Verify Docker is running
docker info
```

### Issue: "Zeek/Suricata logs not found"

**Solution**:
1. Check Docker containers ran successfully:
```bash
docker compose logs zeek
docker compose logs suricata
```

2. If Docker is not available, the pipeline will skip Zeek/Suricata processing.
   You can manually place log files in:
   - `data/derived/zeek/conn.log` and `dns.log`
   - `data/derived/suricata/eve.json`

### Issue: "No detections generated"

**Solution**: Lower detection thresholds in `configs/detector.yaml`:
```yaml
recon_scanning:
  fan_out_threshold: 10  # Lower for testing
```

### Issue: "Cannot connect to Docker daemon"

**Solution**: Ensure Docker Desktop is running (macOS/Windows) or Docker daemon is started (Linux).
The pipeline will continue without Docker but won't process PCAP files.

## Next Steps

1. Read [README.md](README.md) for detailed documentation
2. Review [SECURITY.md](SECURITY.md) for security guidelines
3. Check [docs/PROJECT_BRIEF.md](docs/PROJECT_BRIEF.md) for project overview
