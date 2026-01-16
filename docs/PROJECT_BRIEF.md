# Project Brief: Agent-Assisted Threat Detection from Public Cybersecurity Telemetry

## Executive Summary

This project develops a fully reproducible, offline pipeline for analyzing network PCAP files and generating analyst-ready threat detection reports. The system combines traditional network analysis tools (Zeek, Suricata) with a multi-agent orchestration layer to automate case assembly, evidence gathering, and report generation. The pipeline outputs normalized event data, baseline detections for reconnaissance/scanning and DNS beaconing, and comprehensive case reports with defensive recommendations.

**Key Deliverables (Weeks 1-2)**:
- Complete pipeline from PCAP to case report
- Multi-agent orchestration system (TriageAgent, EvidenceAgent, ReportAgent, CriticAgent)
- Reproducible Docker-based execution environment
- Comprehensive documentation and testing framework

## Motivation

Security Operations Centers (SOCs) face increasing volumes of network telemetry data, making manual analysis time-consuming and error-prone. Traditional SIEM tools provide alerts but require significant analyst effort to:
1. Correlate alerts into coherent cases
2. Gather supporting evidence from multiple log sources
3. Generate actionable reports with defensive recommendations

This project addresses these challenges by:
- **Automating case assembly**: Grouping related detections into cases based on IP addresses, time windows, and detection types
- **Evidence gathering**: Automatically retrieving supporting event rows from normalized telemetry
- **Report generation**: Producing analyst-ready markdown reports with timelines, evidence tables, and recommendations
- **Reproducibility**: Ensuring all runs are traceable with manifests containing hashes, tool versions, and configurations

## Approach

### Architecture

The pipeline follows a modular, agent-based architecture:

1. **Ingest Layer**: Parses Zeek (`conn.log`, `dns.log`) and Suricata (`eve.json`) logs
2. **Normalization Layer**: Converts heterogeneous log formats into a unified schema (Parquet format)
3. **Detection Layer**: Applies baseline algorithms for:
   - Reconnaissance/Scanning: High fan-out connections, bursty traffic patterns
   - DNS Beaconing: Repeated queries, periodic patterns, NXDOMAIN ratios
4. **Agent Orchestration Layer**: Multi-agent system for:
   - **TriageAgent**: Groups detections into candidate cases
   - **EvidenceAgent**: Retrieves supporting rows from normalized events
   - **CriticAgent**: Validates case completeness and requests additional evidence if needed
   - **ReportAgent**: Generates markdown case reports
5. **Reporting Layer**: Produces case reports, run manifests, and agent traces

### Technology Stack

- **Languages**: Python 3.9+
- **Data Processing**: pandas, pyarrow (Parquet)
- **Network Analysis**: Zeek, Suricata (via Docker)
- **Orchestration**: Docker Compose
- **Testing**: pytest
- **Code Quality**: black, ruff, mypy, pre-commit

### Reproducibility

Every pipeline run generates:
- **Run Manifest** (`run_manifest.json`): PCAP hash (SHA256), git commit/branch, tool versions, configuration snapshot, output file hashes
- **Agent Trace** (`agent_trace.jsonl`): JSONL log of all agent steps for full traceability
- **Timestamped Outputs**: All outputs stored in `reports/runs/<timestamp>/`

## Progress Summary

### Weeks 1-2 Accomplishments

**Week 1** focused on establishing the foundational infrastructure and core pipeline components:

1. **Repository Structure**: Created complete directory hierarchy with proper separation of concerns (ingest, normalize, detect, report, agents)
2. **Docker Infrastructure**: Configured Docker Compose with Zeek and Suricata services for PCAP processing
3. **Core Parsers**: Implemented Zeek and Suricata log parsers with robust error handling
4. **Event Normalization**: Developed unified schema normalizer converting heterogeneous logs to Parquet format
5. **Configuration System**: Established YAML-based configuration for detector thresholds and time windows
6. **Testing Framework**: Set up pytest with fixtures and initial test cases

**Week 2** focused on detection algorithms and multi-agent orchestration:

1. **Baseline Detectors**: Implemented recon/scanning and DNS beaconing detection algorithms with configurable thresholds
2. **Multi-Agent System**: Built complete agent orchestration layer with four specialized agents:
   - TriageAgent for case grouping
   - EvidenceAgent for evidence retrieval
   - CriticAgent for validation
   - ReportAgent for markdown generation
3. **Case Assembly**: Developed time-window and IP-based case grouping logic
4. **Report Generation**: Created analyst-ready markdown reports with evidence tables, timelines, and defensive recommendations
5. **Manifest System**: Implemented run manifest generation with file hashing and tool version tracking
6. **Documentation**: Completed comprehensive documentation including README, SECURITY.md, and project documentation suite

**Key Achievements**:
- ✅ Fully reproducible pipeline from PCAP to case report
- ✅ Multi-agent orchestration with trace logging (TriageAgent, EvidenceAgent, CriticAgent, ReportAgent)
- ✅ Docker-based execution environment (Zeek, Suricata, Python services)
- ✅ Comprehensive test coverage (pytest with fixtures)
- ✅ Enterprise-level documentation (README, SECURITY, PROJECT_BRIEF, PROJECT_CHARTER, DATA_PLAN, SOC_ASK_OFFER_MEMO)
- ✅ Sample PCAP download scripts for testing
- ✅ Run verification script (`make verify`)
- ✅ Professional case reports with executive summaries, timelines, evidence tables, and defensive recommendations

**Generated Artifacts** (from test run with `tiny_sample.pcap`):
- `reports/runs/20260115_190601/case_report.md` - Case report with executive summary
- `reports/runs/20260115_190601/run_manifest.json` - Run manifest with PCAP hash (SHA256: 4fbac81003db3bf933445f4635d590e0b687b3ca426c151961257b0c58044c4d), tool versions, config snapshot
- `reports/runs/20260115_190601/agent_trace.jsonl` - Agent orchestration trace (orchestrator, triage, evidence, critic, report agents)
- `reports/runs/20260115_190601/detections.jsonl` - Baseline detections (recon/scanning, DNS beaconing)
- `reports/runs/20260115_190601/events.parquet` - Normalized events (unified schema from Zeek + Suricata)
- `data/normalized/events_20260115_190601.parquet` - Normalized events backup

## Week 1 Plan

### Objectives
- Establish repository structure and development environment
- Implement core ingest and normalization components
- Set up Docker infrastructure for Zeek and Suricata
- Create configuration system and testing framework

### Tasks

1. **Repository Setup** (Day 1-2)
   - Create directory structure (`src/`, `data/`, `configs/`, `tests/`, `docs/`)
   - Set up Python project (`pyproject.toml`, `.gitignore`, `.editorconfig`)
   - Configure pre-commit hooks (black, ruff, mypy)
   - Create Makefile with common targets

2. **Docker Infrastructure** (Day 2-3)
   - Create `docker-compose.yml` with Zeek and Suricata services
   - Write `Dockerfile` for Python pipeline service
   - Test PCAP processing with sample files
   - Configure volume mounts and networking

3. **Ingest Module** (Day 3-4)
   - Implement `ZeekParser` for `conn.log` and `dns.log`
   - Implement `SuricataParser` for `eve.json`
   - Add error handling and logging
   - Write unit tests with sample log files

4. **Normalization Module** (Day 4-5)
   - Design unified event schema
   - Implement `EventNormalizer` for Zeek and Suricata events
   - Handle timestamp conversion and field mapping
   - Output to Parquet format
   - Write integration tests

5. **Configuration System** (Day 5)
   - Create `configs/detector.yaml` with detector thresholds
   - Implement YAML configuration loader
   - Add validation for configuration values

6. **Testing Framework** (Day 5)
   - Set up pytest with fixtures
   - Create sample test data (mock logs)
   - Write initial test cases for parsers and normalizer

### Deliverables
- Functional ingest and normalization pipeline
- Docker Compose setup working with sample PCAPs
- Basic test suite passing
- Configuration system operational

## Week 2 Plan

### Objectives
- Implement baseline detection algorithms
- Build multi-agent orchestration system
- Generate case reports and run manifests
- Complete documentation and testing

### Tasks

1. **Baseline Detectors** (Day 1-2)
   - Implement `BaselineDetector` class
   - Develop recon/scanning algorithm (fan-out, burst detection)
   - Develop DNS beaconing algorithm (repeated queries, periodicity)
   - Add configurable thresholds and time windows
   - Write unit tests with synthetic data

2. **Multi-Agent System** (Day 2-4)
   - Implement `AgentOrchestrator` for coordination
   - Build `TriageAgent` for case grouping (IP, time window, detection type)
   - Build `EvidenceAgent` for evidence retrieval from normalized events
   - Build `CriticAgent` for validation and feedback loops
   - Build `ReportAgent` for markdown report generation
   - Implement agent trace logging (`agent_trace.jsonl`)

3. **Case Assembly** (Day 3-4)
   - Develop case grouping logic (time windows, IP correlation)
   - Implement evidence bundling (top N supporting rows)
   - Add case ID generation and tracking

4. **Report Generation** (Day 4-5)
   - Generate markdown case reports with:
     - Executive summary
     - Timeline of events
     - Evidence table
     - Confidence scores and limitations
     - Defensive action recommendations
   - Implement `ManifestGenerator` for run metadata
   - Add file hashing (SHA256) for reproducibility

5. **Integration and Testing** (Day 5)
   - End-to-end pipeline test with sample PCAP
   - Validate all outputs (Parquet, reports, manifests, traces)
   - Test agent orchestration with various detection scenarios
   - Performance testing with larger PCAP files

6. **Documentation** (Day 5)
   - Complete README.md with quickstart guide
   - Write SECURITY.md with defensive-only guidance
   - Create PROJECT_BRIEF.md (this document)
   - Write PROJECT_CHARTER.md
   - Write DATA_PLAN.md
   - Write SOC_ASK_OFFER_MEMO.md

### Deliverables
- Complete pipeline from PCAP to case report
- Multi-agent orchestration system operational
- Comprehensive test suite
- Full documentation suite
- Run manifest and agent trace outputs

## Success Criteria

By end of Week 2, the pipeline must:

1. ✅ Process PCAP files and generate Zeek/Suricata logs
2. ✅ Normalize events into unified Parquet schema
3. ✅ Detect recon/scanning and DNS beaconing with configurable thresholds
4. ✅ Group detections into cases using multi-agent orchestration
5. ✅ Generate analyst-ready case reports with evidence and recommendations
6. ✅ Produce run manifests with hashes, versions, and configurations
7. ✅ Log all agent steps to trace file
8. ✅ Run entirely in Docker with Docker Compose
9. ✅ Pass comprehensive test suite
10. ✅ Include complete documentation

## Next Steps (Post Week 2)

- **Week 3+**: Enhanced detection algorithms (ML-based, anomaly detection)
- **Week 4+**: Integration with SIEM platforms (Splunk, Elastic)
- **Week 5+**: Real-time streaming analysis capabilities
- **Week 6+**: Advanced agent capabilities (LLM integration for report writing)

---

**Status**: Weeks 1-2 Complete ✅
**Last Updated**: [Current Date]
