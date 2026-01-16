# Exact Commands to Reproduce from Fresh Clone

## Complete Reproduction Steps

### 1. Clone Repository
```bash
git clone https://github.com/UdayIND/Uday-Independent-Study-Prv.git
cd Uday-Independent-Study-Prv
```

### 2. Preflight Check
```bash
make preflight
```
**Expected**: All checks pass (0 errors, 0 warnings)

### 3. Setup Environment
```bash
make setup
source venv/bin/activate  # or: . venv/bin/activate
```

### 4. Run Tests
```bash
make test
```
**Expected**: 15 tests pass

### 5. Download Sample PCAP
```bash
bash scripts/download_tiny_pcap.sh
```
**Expected**: PCAP downloaded to `data/raw/tiny_sample.pcap` (~248 KB)

### 6. Run Pipeline
```bash
make run PCAP=data/raw/tiny_sample.pcap
```
**Expected**: Pipeline completes successfully, creates `reports/runs/<timestamp>/`

### 7. Verify Outputs
```bash
make verify
```
**Expected**: All required outputs verified

### 8. View Results
```bash
# Find latest run
LATEST_RUN=$(ls -t reports/runs/ | head -1)

# View case report
cat "reports/runs/$LATEST_RUN/case_report.md"

# View manifest
cat "reports/runs/$LATEST_RUN/run_manifest.json" | python3 -m json.tool

# View agent trace
cat "reports/runs/$LATEST_RUN/agent_trace.jsonl" | python3 -m json.tool

# List all outputs
ls -lh "reports/runs/$LATEST_RUN/"
```

## Expected Outputs

After running the pipeline, you should see:

1. **Run Directory**: `reports/runs/<timestamp>/` with:
   - `case_report.md` - Case report (may be empty if no detections)
   - `run_manifest.json` - Run metadata with hashes
   - `agent_trace.jsonl` - Agent orchestration steps
   - `detections.jsonl` - Baseline detections (may be empty)
   - `events.parquet` - Normalized events DataFrame

2. **Normalized Events**: `data/normalized/events_<timestamp>.parquet`

3. **Zeek Logs** (if Docker works): `data/derived/zeek/conn.log`, `dns.log`

4. **Suricata Logs** (if Docker works): `data/derived/suricata/eve.json`

## Troubleshooting

**If Zeek/Suricata logs are not generated**:
- This is acceptable - the pipeline handles missing logs gracefully
- Pipeline will still produce all required outputs
- Check Docker logs: `docker compose logs zeek` and `docker compose logs suricata`

**If detections.jsonl is empty**:
- This is valid when no detections are found
- Expected behavior for small/sample PCAPs
- Lower thresholds in `configs/detector.yaml` for testing

**If verify script fails**:
- Check that `reports/runs/` directory exists
- Ensure at least one run directory is present
- Run directory names should match pattern: `YYYYMMDD_HHMMSS`
