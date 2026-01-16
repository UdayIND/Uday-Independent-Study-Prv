# 60-Second Demo Script

Quick demonstration of the SOC-Informed Discovery pipeline.

## Prerequisites
- Docker Desktop running (or Docker daemon)
- Python 3.9+ installed
- Virtual environment activated (or use `make setup` first)

## Demo Steps

### 1. Setup (if not already done)
```bash
cd "/Users/udayhome/Desktop/Uday Independent Study Prv"
make setup
source venv/bin/activate  # or: . venv/bin/activate
```

### 2. Download Sample PCAP
```bash
bash scripts/download_tiny_pcap.sh
```

### 3. Run Pipeline
```bash
make run PCAP=data/raw/tiny_sample.pcap
```

### 4. Verify Outputs
```bash
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
```

### 6. Check Output Files
```bash
ls -lh "reports/runs/$LATEST_RUN/"
# Should show:
# - case_report.md
# - run_manifest.json
# - agent_trace.jsonl
# - detections.jsonl
# - events.parquet
```

## Expected Outputs

After running the pipeline, you should see:

1. **Zeek logs** in `data/derived/zeek/` (conn.log, dns.log)
2. **Suricata logs** in `data/derived/suricata/` (eve.json)
3. **Normalized events** in `data/normalized/events_<timestamp>.parquet`
4. **Run outputs** in `reports/runs/<timestamp>/`:
   - `case_report.md` - Analyst-ready case report
   - `run_manifest.json` - Run metadata with hashes
   - `agent_trace.jsonl` - Agent orchestration trace
   - `detections.jsonl` - Baseline detections
   - `events.parquet` - Normalized events

## Troubleshooting

**Docker not running?**
- Start Docker Desktop (macOS/Windows) or `sudo systemctl start docker` (Linux)
- Pipeline will still run but skip Zeek/Suricata processing

**No detections?**
- This is normal for small/sample PCAPs
- Lower thresholds in `configs/detector.yaml` for testing
- Use a larger PCAP with actual network traffic

**Tests failing?**
- Run: `make test` to see specific failures
- Ensure virtual environment is activated: `source venv/bin/activate`
