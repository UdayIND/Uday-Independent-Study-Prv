# Project Charter: Agent-Assisted Threat Detection Pipeline

## Project Overview

**Project Name**: Agent-Assisted Threat Detection from Public Cybersecurity Telemetry (SOC-Informed Discovery)

**Project Duration**: Independent Study (Weeks 1-2 Initial Phase)

**Project Type**: Research & Development

**Primary Objective**: Develop a fully reproducible, offline pipeline for analyzing network PCAP files and generating analyst-ready threat detection reports using multi-agent orchestration.

## Problem Statement

Security Operations Centers (SOCs) process vast amounts of network telemetry data daily. Traditional SIEM tools generate alerts but require significant manual analyst effort to:

1. **Correlate alerts** into coherent security cases
2. **Gather supporting evidence** from multiple log sources (Zeek, Suricata, firewall logs)
3. **Generate actionable reports** with defensive recommendations
4. **Maintain reproducibility** for forensic analysis and compliance

This manual process is:
- **Time-consuming**: Analysts spend hours per case on data gathering
- **Error-prone**: Manual correlation can miss related events
- **Inconsistent**: Different analysts may produce different reports for similar cases
- **Not reproducible**: Lack of manifests makes it difficult to verify or reproduce analyses

## Project Scope

### In Scope (Weeks 1-2)

✅ **Core Pipeline Components**:
- PCAP ingestion and processing with Zeek and Suricata
- Event normalization into unified schema (Parquet)
- Baseline detection algorithms (recon/scanning, DNS beaconing)
- Multi-agent orchestration system
- Case report generation
- Run manifest generation

✅ **Infrastructure**:
- Docker Compose setup for Zeek, Suricata, and Python services
- Configuration system (YAML-based)
- Testing framework (pytest)
- Code quality tools (black, ruff, mypy, pre-commit)

✅ **Documentation**:
- README with quickstart guide
- SECURITY.md with defensive-only guidance
- Project documentation suite (Brief, Charter, Data Plan, SOC Memo)

### Out of Scope (Weeks 1-2)

❌ **Real-time Analysis**: Pipeline is offline/batch-oriented
❌ **SIEM Integration**: No direct integration with Splunk, Elastic, etc.
❌ **Machine Learning**: Baseline algorithms only (no ML models)
❌ **LLM Integration**: Report generation is template-based (not LLM-powered)
❌ **GUI/Web Interface**: Command-line and file-based outputs only
❌ **Database Storage**: File-based storage (Parquet, JSON, Markdown)

### Future Scope (Post Week 2)

- Enhanced detection algorithms (ML-based, anomaly detection)
- SIEM platform integrations
- Real-time streaming analysis
- LLM-powered report generation
- Web-based dashboard
- Database backend (PostgreSQL, MongoDB)

## Objectives

### Primary Objectives

1. **Reproducibility**: Every pipeline run generates a manifest with:
   - PCAP file hash (SHA256)
   - Git commit and branch
   - Tool versions (Python, Zeek, Suricata)
   - Configuration snapshot
   - Output file hashes

2. **Automation**: Multi-agent system automates:
   - Case assembly from raw detections
   - Evidence gathering from normalized events
   - Report generation with defensive recommendations

3. **Traceability**: All agent steps logged to `agent_trace.jsonl` for full audit trail

4. **Analyst-Ready Outputs**: Case reports include:
   - Executive summary
   - Timeline of events
   - Evidence table with supporting rows
   - Confidence scores and limitations
   - Defensive action recommendations

### Success Criteria

By end of Week 2:

- ✅ Pipeline processes PCAP → Zeek logs → Suricata logs → normalized events → detections → cases → reports
- ✅ Multi-agent orchestration system operational with trace logging
- ✅ Docker Compose setup runs end-to-end pipeline
- ✅ Test suite passes with >80% code coverage
- ✅ Documentation complete and professional
- ✅ All outputs include run manifests with hashes and versions

## Deliverables

### Code Deliverables

1. **Pipeline Modules**:
   - `src/ingest/`: Zeek and Suricata parsers
   - `src/normalize/`: Event normalizer
   - `src/detect_baseline/`: Baseline detectors
   - `src/agents/`: Multi-agent orchestration
   - `src/report/`: Report and manifest generators

2. **Infrastructure**:
   - `docker-compose.yml`: Zeek, Suricata, Python services
   - `Dockerfile`: Python pipeline container
   - `Makefile`: Common commands (setup, run, test, clean)
   - `configs/`: Detector and tool configurations

3. **Testing**:
   - `tests/`: Pytest test suite with fixtures
   - Sample test data (mock logs)

### Documentation Deliverables

1. **README.md**: Quickstart guide, prerequisites, outputs, troubleshooting
2. **SECURITY.md**: Defensive-only guidance, data handling, compliance
3. **docs/PROJECT_BRIEF.md**: Executive summary, motivation, approach, progress
4. **docs/PROJECT_CHARTER.md**: This document (scope, objectives, deliverables)
5. **docs/DATA_PLAN.md**: Data sources, schemas, processing workflows
6. **docs/SOC_ASK_OFFER_MEMO.md**: SOC team collaboration proposal

### Output Deliverables (Per Run)

1. **Zeek Logs**: `data/derived/zeek/conn.log`, `dns.log`
2. **Suricata Logs**: `data/derived/suricata/eve.json`
3. **Normalized Events**: `reports/runs/<timestamp>/events.parquet`
4. **Case Report**: `reports/runs/<timestamp>/case_report.md`
5. **Run Manifest**: `reports/runs/<timestamp>/run_manifest.json`
6. **Agent Trace**: `reports/runs/<timestamp>/agent_trace.jsonl`

## Stakeholders

### Primary Stakeholders

- **Security Analysts**: End users who will use the pipeline for threat detection
- **SOC Managers**: Decision makers evaluating the tool for SOC operations
- **Independent Study Advisor**: Academic supervisor reviewing progress

### Secondary Stakeholders

- **DevOps Engineers**: May deploy and maintain the pipeline infrastructure
- **Compliance Officers**: May review outputs for audit requirements
- **Security Researchers**: May use the tool for research purposes

## Constraints and Assumptions

### Constraints

1. **Time**: 2-week initial phase (Weeks 1-2)
2. **Resources**: Local development environment, Docker Desktop
3. **Data**: PCAP files must be provided (not generated by pipeline)
4. **Scope**: Baseline detection algorithms only (no ML in initial phase)

### Assumptions

1. **PCAP Availability**: Users have access to PCAP files for analysis
2. **Docker Access**: Users can run Docker and Docker Compose
3. **Python Environment**: Python 3.9+ available locally or in Docker
4. **Network Access**: Docker images can be pulled from Docker Hub
5. **Storage**: Sufficient disk space for PCAP files and derived logs

## Risks and Mitigations

### Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Zeek/Suricata parsing errors | High | Medium | Robust error handling, fallback parsing |
| Performance with large PCAPs | Medium | Medium | Streaming processing, chunking |
| Docker compatibility issues | Medium | Low | Test on multiple platforms, provide alternatives |
| Agent orchestration bugs | High | Low | Comprehensive testing, trace logging |

### Project Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Scope creep | High | Medium | Clear scope definition, weekly reviews |
| Documentation gaps | Medium | Low | Documentation checklist, peer review |
| Testing coverage insufficient | Medium | Low | Code coverage targets, integration tests |

## Timeline

### Week 1: Foundation
- Days 1-2: Repository setup, Docker infrastructure
- Days 3-4: Ingest and normalization modules
- Day 5: Configuration system, testing framework

### Week 2: Detection and Agents
- Days 1-2: Baseline detectors
- Days 2-4: Multi-agent system
- Day 4-5: Report generation, integration testing
- Day 5: Documentation completion

## Success Metrics

### Quantitative Metrics

- **Pipeline Execution Time**: < 5 minutes for 100MB PCAP
- **Test Coverage**: > 80% code coverage
- **Documentation Completeness**: 100% of planned docs delivered
- **Reproducibility**: 100% of runs generate manifests with hashes

### Qualitative Metrics

- **Code Quality**: Passes all linting and type checking
- **Documentation Quality**: Clear, professional, actionable
- **Usability**: Analysts can run pipeline with minimal setup
- **Traceability**: Agent steps fully logged and auditable

## Approval and Sign-off

**Project Owner**: Uday
**Advisor**: [To be filled]
**Date**: [Current Date]

---

**Status**: Active
**Version**: 1.0
**Last Updated**: [Current Date]
