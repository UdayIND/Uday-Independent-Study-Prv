# Reproduction Guide

## Exact Commands to Reproduce Everything from a Fresh Clone

### 1. Clone Repository
```bash
git clone https://github.com/UdayIND/Uday-Independent-Study-Prv.git
cd Uday-Independent-Study-Prv
```

### 2. Setup Environment
```bash
# Install dependencies (creates venv automatically)
make setup

# Activate virtual environment
source venv/bin/activate
```

### 3. Download Sample PCAP
```bash
# Small sample for quick testing (~250KB)
bash scripts/download_tiny_pcap.sh

# Or larger sample (if available)
bash scripts/download_sample_pcap.sh
```

### 4. Run Pipeline
```bash
# Ensure Docker is running (required for Zeek/Suricata)
docker info

# Run pipeline
make run PCAP=data/raw/tiny_sample.pcap

# Verify outputs
make verify
```

### 5. View Results
```bash
# Find latest run
LATEST_RUN=$(ls -t reports/runs/ | head -1)

# View case report
cat "reports/runs/$LATEST_RUN/case_report.md"

# View manifest
cat "reports/runs/$LATEST_RUN/run_manifest.json" | python3 -m json.tool

# View agent trace
head -5 "reports/runs/$LATEST_RUN/agent_trace.jsonl" | python3 -m json.tool

# List all outputs
ls -lh "reports/runs/$LATEST_RUN/"
```

### 6. Run Tests
```bash
# Run test suite
make test

# Run specific test
pytest tests/test_normalizer.py -v
```

## Expected Outputs

After running the pipeline, you should see:

1. **Zeek Logs**: `data/derived/zeek/conn.log`, `dns.log`
2. **Suricata Logs**: `data/derived/suricata/eve.json`
3. **Normalized Events**:
   - `reports/runs/<timestamp>/events.parquet`
   - `data/normalized/events_<timestamp>.parquet`
4. **Run Outputs** in `reports/runs/<timestamp>/`:
   - `case_report.md` - Analyst-ready case report
   - `run_manifest.json` - Run metadata with hashes
   - `agent_trace.jsonl` - Agent orchestration trace
   - `detections.jsonl` - Baseline detections
   - `events.parquet` - Normalized events

## Troubleshooting

**Docker not running?**
- Start Docker Desktop (macOS/Windows) or `sudo systemctl start docker` (Linux)
- Pipeline will continue but skip Zeek/Suricata processing

**Tests failing?**
- Ensure virtual environment is activated: `source venv/bin/activate`
- Check Python version: `python3 --version` (requires 3.9+)

**No detections?**
- Normal for small/sample PCAPs
- Lower thresholds in `configs/detector.yaml` for testing
- Use a larger PCAP with actual network traffic

## Verification Checklist

After running the pipeline, verify:

- [ ] `reports/runs/<timestamp>/case_report.md` exists and is non-empty
- [ ] `reports/runs/<timestamp>/run_manifest.json` contains PCAP hash and tool versions
- [ ] `reports/runs/<timestamp>/agent_trace.jsonl` contains agent steps
- [ ] `reports/runs/<timestamp>/detections.jsonl` exists (may be empty)
- [ ] `reports/runs/<timestamp>/events.parquet` exists and is non-empty
- [ ] `data/normalized/events_<timestamp>.parquet` exists
- [ ] `make verify` passes without errors
