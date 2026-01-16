# SOC Ask/Offer Memo: Agent-Assisted Threat Detection Pipeline

**To**: SOC Management Team
**From**: Independent Study Project Team
**Date**: [Current Date]
**Subject**: Collaboration Opportunity - Agent-Assisted Threat Detection Pipeline

## Executive Summary

We are developing an **Agent-Assisted Threat Detection Pipeline** that automates case assembly, evidence gathering, and report generation from network telemetry data. We seek collaboration with the SOC team to:

1. **Validate** detection algorithms and case assembly logic with real-world data
2. **Gather feedback** on report formats and analyst workflows
3. **Identify** integration opportunities with existing SOC tools

In return, we offer:

1. **Open-source pipeline** for SOC use (fully reproducible, Docker-based)
2. **Customizable detection algorithms** tailored to SOC needs
3. **Documentation and training** materials for SOC analysts

## What We're Building

### Pipeline Overview

A fully reproducible, offline pipeline that:

- **Processes PCAP files** through Zeek and Suricata
- **Normalizes events** into unified schema (Parquet format)
- **Detects threats** using baseline algorithms:
  - Reconnaissance/Scanning (high fan-out, bursty traffic)
  - DNS Beaconing (repeated queries, periodic patterns)
- **Assembles cases** using multi-agent orchestration:
  - Groups related detections
  - Retrieves supporting evidence
  - Validates case completeness
- **Generates reports** with:
  - Executive summaries
  - Event timelines
  - Evidence tables
  - Defensive recommendations

### Key Features

✅ **Reproducibility**: Every run generates a manifest with hashes, tool versions, configurations
✅ **Traceability**: All agent steps logged to JSONL trace files
✅ **Analyst-Ready**: Markdown reports with actionable recommendations
✅ **Docker-Based**: Runs entirely in containers (Zeek, Suricata, Python)

## What We're Asking For

### 1. Validation Opportunities

**Request**: Access to anonymized PCAP files or log samples for testing

**Purpose**: Validate detection algorithms against real-world attack patterns

**Data Requirements**:
- Anonymized PCAP files (internal IPs redacted)
- Or: Sample Zeek/Suricata logs from known incidents
- Size: 10MB - 100MB per sample

**Privacy**: We commit to:
- Not storing sensitive data
- Using anonymized samples only
- Following SOC data handling policies

### 2. Analyst Feedback

**Request**: 2-3 SOC analysts review sample case reports

**Purpose**: Ensure reports meet analyst needs and workflows

**Time Commitment**: 1-2 hours per analyst (review 3-5 sample reports)

**Feedback Areas**:
- Report format and structure
- Evidence presentation
- Defensive recommendations clarity
- Missing information or fields

### 3. Integration Opportunities

**Request**: Discussion on SOC tool ecosystem

**Purpose**: Identify integration points with existing SOC tools

**Topics**:
- SIEM platforms (Splunk, Elastic, etc.)
- Ticketing systems (ServiceNow, Jira)
- Threat intelligence feeds
- Case management systems

## What We're Offering

### 1. Open-Source Pipeline

**Deliverable**: Complete pipeline codebase (MIT License)

**Benefits**:
- Fully reproducible analysis
- Customizable detection algorithms
- Docker-based deployment
- Comprehensive documentation

**Timeline**: Available end of Week 2

### 2. Customizable Detection Algorithms

**Offer**: Tailor detection thresholds and algorithms to SOC needs

**Examples**:
- Adjust fan-out thresholds for recon/scanning
- Customize DNS beaconing parameters
- Add SOC-specific detection rules

**Timeline**: Ongoing collaboration

### 3. Documentation and Training

**Deliverable**:
- User guide for SOC analysts
- Training materials (slides, videos)
- Troubleshooting guide
- Best practices documentation

**Timeline**: Available end of Week 2

### 4. Integration Support

**Offer**: Assist with integration into SOC workflows

**Examples**:
- SIEM connector development
- API endpoints for case ingestion
- Custom report formats

**Timeline**: Post Week 2 (future phase)

## Proposed Collaboration Timeline

### Week 2 (Current)
- **Deliver**: Initial pipeline with baseline detectors
- **Request**: Initial feedback on approach and requirements

### Week 3-4 (Proposed)
- **Deliver**: Enhanced pipeline with SOC feedback incorporated
- **Request**: Validation with anonymized samples
- **Deliver**: Analyst training materials

### Week 5+ (Future)
- **Deliver**: Integration prototypes (if applicable)
- **Ongoing**: Support and maintenance

## Success Metrics

### For SOC Team

- **Time Savings**: Reduced analyst time per case (target: 30-50%)
- **Consistency**: Standardized case reports across analysts
- **Reproducibility**: Ability to reproduce analyses for audits
- **Traceability**: Full audit trail of detection and case assembly steps

### For Project Team

- **Validation**: Detection algorithms validated against real-world data
- **Feedback**: Analyst feedback incorporated into report formats
- **Integration**: Understanding of SOC tool ecosystem for future integration

## Next Steps

1. **SOC Review**: SOC team reviews this memo and identifies interested stakeholders
2. **Initial Meeting**: 30-minute meeting to discuss collaboration scope
3. **Data Agreement**: Establish data sharing agreement (anonymization, retention)
4. **Feedback Sessions**: Schedule analyst feedback sessions (Week 3-4)
5. **Integration Discussion**: Explore integration opportunities (Week 5+)

## Contact Information

**Project Lead**: Uday
**Email**: [To be filled]
**Availability**: Flexible, can accommodate SOC schedules

## Appendix: Sample Outputs

### Case Report Sample

```markdown
## Case 1: CASE_0001

### Summary
**Detection Type:** recon_scanning
**Source IP:** 192.168.1.100
**Detection Count:** 15
**Evidence Rows:** 42

### Timeline
- **Start:** 2024-01-15 10:30:00
- **End:** 2024-01-15 10:35:00

### Evidence
[Evidence table with top 20 rows]

### Recommended Defensive Actions
1. Monitor traffic from source IP
2. Review firewall logs
3. Check endpoint logs
4. Document findings
```

### Run Manifest Sample

```json
{
    "run_timestamp": "20240115_103000",
    "pcap_file": "capture.pcap",
    "pcap_hash": "sha256:abc123...",
    "git_commit": "def456...",
    "tool_versions": {
        "python": "3.11.0",
        "zeek": "6.0.0",
        "suricata": "7.0.0"
    }
}
```

---

**Thank you for considering this collaboration opportunity!**

We look forward to working with the SOC team to improve threat detection capabilities and analyst workflows.
