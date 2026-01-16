# Hardening Checklist - Week 2 Demo Readiness

## ✅ Repo Sanity & Conventions

- [x] **Core Files Present:**
  - README.md ✓
  - QUICKSTART.md ✓
  - Makefile ✓
  - docker-compose.yml ✓
  - pyproject.toml ✓
  - SECURITY.md ✓
  - docs/ folder ✓
  - src/ folder ✓
  - tests/ folder ✓

- [x] **Data Directory:**
  - `data/raw/` contains `.gitkeep` with explanation ✓
  - PCAP files are gitignored (`data/raw/*.pcap`, `data/raw/*.pcapng`) ✓
  - Verified: `tiny_sample.pcap` is gitignored ✓

- [x] **Output Directories:**
  - `reports/runs/` is gitignored ✓
  - `data/derived/` is gitignored ✓
  - `data/normalized/` is gitignored ✓
  - Large generated files will not be committed ✓

## ✅ Makefile Correctness

- [x] **Docker Compose:**
  - Uses `docker compose` (v2.x) not legacy `docker-compose` ✓
  - Variable: `DOCKER_COMPOSE := docker compose` ✓

- [x] **Targets Present:**
  - `setup` - Creates venv, installs dependencies ✓
  - `run PCAP=...` - Runs pipeline with PCAP file ✓
  - `test` - Runs pytest test suite ✓
  - `clean` - Removes generated files ✓
  - `verify` - Verifies pipeline outputs ✓
  - `preflight` - NEW: Checks prerequisites ✓

- [x] **Error Messages:**
  - Clear error if PCAP not provided ✓
  - Clear error if PCAP file not found ✓
  - Helpful messages for missing dependencies ✓

## ✅ Config Hygiene

- [x] **Configuration Files:**
  - `configs/detector.yaml` contains all thresholds ✓
  - No hardcoded thresholds in source code ✓
  - Config loads successfully (verified) ✓

- [x] **Conservative Thresholds:**
  - Recon scanning: `fan_out_threshold: 50` (conservative) ✓
  - DNS beaconing: `repeated_query_threshold: 10` (conservative) ✓
  - Comments indicate conservative values ✓

## ✅ Agentic Trace Clarity

- [x] **Agent Orchestration:**
  - TriageAgent → EvidenceAgent → CriticAgent → ReportAgent ✓
  - All agent steps logged to `agent_trace.jsonl` ✓

- [x] **CriticAgent Validation:**
  - Checks minimum evidence rows ✓
  - Checks confidence threshold ✓
  - Checks evidence references in report ✓
  - Requests additional evidence if validation fails ✓
  - Re-validates after evidence expansion ✓

## ✅ Report Quality (Template)

- [x] **Required Sections:**
  - Executive Summary ✓
  - Case Details ✓
  - Timeline (formatted table) ✓
  - Evidence Table (top 20 rows) ✓
  - Detector Reasoning ✓
  - Confidence & Limitations ✓
  - Recommended Defensive Actions ✓

- [x] **Security:**
  - No offensive instructions ✓
  - No exploit guidance ✓
  - All recommendations are defensive-only ✓
  - Professional, readable writing ✓

## ✅ Documentation Truthfulness

- [x] **README.md:**
  - Accurate prerequisites ✓
  - Exact commands provided ✓
  - Output locations clearly stated ✓
  - Troubleshooting section present ✓

- [x] **QUICKSTART.md:**
  - Minimal, exact instructions ✓
  - 60-second demo script added ✓
  - File locations specified ✓
  - Troubleshooting included ✓

- [x] **No Unverifiable Claims:**
  - All documented features exist in code ✓
  - Commands match actual implementation ✓

## ✅ Preflight Command

- [x] **scripts/preflight.sh:**
  - Checks Docker installed + running ✓
  - Checks Docker Compose works ✓
  - Checks required folders exist ✓
  - Checks Python version (3.9+) ✓
  - Checks virtual environment ✓
  - Checks configuration files ✓
  - Checks .gitignore ✓
  - Provides clear summary ✓

- [x] **Makefile Integration:**
  - `make preflight` target added ✓
  - Added to help output ✓

## ✅ Git Hygiene

- [x] **No Secrets:**
  - No API keys, tokens, or passwords found ✓
  - `.env` files are gitignored ✓

- [x] **No Large Files:**
  - PCAP files gitignored ✓
  - Parquet files gitignored ✓
  - Report outputs gitignored ✓
  - Virtual environment gitignored ✓

## Summary

**Status: ✅ READY TO TEST**

All hardening checks passed. The repository is:
- Properly structured with all required files
- Using correct Docker Compose v2 syntax
- Configurable with conservative thresholds
- Fully agentic with trace logging
- Producing professional, defensive-only reports
- Well-documented with accurate instructions
- Includes preflight checks for prerequisites
- Secure with no secrets or large files committed

**Remaining Actions:**
- None - repository is demo-ready

**Next Step:**
Run `make preflight` to verify environment, then `make run PCAP=data/raw/tiny_sample.pcap` to test the pipeline.
