# Demo Checklist - 10 Items for Meeting

## Pre-Demo Setup (Before Meeting)

1. **Repository Cloned and Ready**
   - [ ] Repository cloned: `git clone https://github.com/UdayIND/Uday-Independent-Study-Prv.git`
   - [ ] Preflight passed: `make preflight` (all checks green)
   - [ ] Tests passing: `make test` (15/15 passed)

## Demo Items (10 Bullets)

### 1. Repository Structure ✅
**Show**: `ls -R src/ configs/ docs/`
**Say**: "Complete modular structure with ingest, normalize, detect, agents, and report modules"

### 2. Multi-Agent Architecture ✅
**Show**: `cat src/agents/orchestrator.py | head -50`
**Say**: "Four-agent orchestration: TriageAgent groups detections, EvidenceAgent retrieves supporting rows, CriticAgent validates completeness, ReportAgent generates markdown reports"

### 3. Docker Integration ✅
**Show**: `cat docker-compose.yml`
**Say**: "Docker Compose setup with Zeek, Suricata, and Python services. Uses Docker Compose v2 syntax"

### 4. Configuration System ✅
**Show**: `cat configs/detector.yaml`
**Say**: "All thresholds configurable via YAML. Conservative defaults to reduce false positives"

### 5. Pipeline Execution ✅
**Show**: `make run PCAP=data/raw/tiny_sample.pcap`
**Say**: "Single command runs entire pipeline: Zeek/Suricata processing, normalization, detection, agent orchestration, report generation"

### 6. Generated Outputs ✅
**Show**: `ls -lh reports/runs/<latest>/`
**Say**: "Five required outputs: case_report.md, run_manifest.json, agent_trace.jsonl, detections.jsonl, events.parquet"

### 7. Run Manifest (Reproducibility) ✅
**Show**: `cat reports/runs/<latest>/run_manifest.json | python3 -m json.tool`
**Say**: "Complete reproducibility: PCAP hash (SHA256), git commit, tool versions, config snapshot, output file hashes"

### 8. Agent Trace (Traceability) ✅
**Show**: `head -5 reports/runs/<latest>/agent_trace.jsonl | python3 -m json.tool`
**Say**: "Full agent traceability: Every agent step logged with JSONL format for audit trail"

### 9. Case Report Quality ✅
**Show**: `cat reports/runs/<latest>/case_report.md`
**Say**: "Analyst-ready reports with executive summary, timeline, evidence table, detector reasoning, confidence scores, and defensive recommendations only"

### 10. Verification Script ✅
**Show**: `make verify`
**Say**: "Automated verification confirms all outputs present and non-empty. Pipeline is production-ready"

## Quick Demo Script (60 seconds)

```bash
# 1. Show structure
ls -R src/ | head -20

# 2. Run pipeline
make run PCAP=data/raw/tiny_sample.pcap

# 3. Show outputs
LATEST_RUN=$(ls -t reports/runs/ | head -1)
ls -lh "reports/runs/$LATEST_RUN/"

# 4. Show manifest
cat "reports/runs/$LATEST_RUN/run_manifest.json" | python3 -m json.tool | head -20

# 5. Show agent trace
head -3 "reports/runs/$LATEST_RUN/agent_trace.jsonl" | python3 -m json.tool

# 6. Verify
make verify
```

## Key Talking Points

1. **Reproducibility**: Every run generates a manifest with hashes and versions
2. **Traceability**: All agent steps logged for full audit trail
3. **Modularity**: Clean separation of concerns (ingest, normalize, detect, agents, report)
4. **Configurability**: All thresholds in YAML, no hardcoded values
5. **Defensive-Only**: All recommendations are defensive, no offensive instructions
6. **Graceful Degradation**: Pipeline handles missing logs gracefully
7. **Professional Outputs**: Analyst-ready reports with proper structure
8. **Test Coverage**: 15 tests passing with pytest fixtures
9. **Documentation**: Complete docs (README, QUICKSTART, PROJECT_BRIEF, etc.)
10. **Git Hygiene**: PCAP files properly gitignored, no secrets committed

## Files to Have Open

1. `README.md` - Overview and quickstart
2. `reports/runs/<latest>/case_report.md` - Example case report
3. `reports/runs/<latest>/run_manifest.json` - Reproducibility manifest
4. `reports/runs/<latest>/agent_trace.jsonl` - Agent trace
5. `configs/detector.yaml` - Configuration example
