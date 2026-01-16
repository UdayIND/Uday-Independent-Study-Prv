# Data Plan: SOC-Informed Discovery Pipeline

## Overview

This document describes the data sources, schemas, processing workflows, and data management practices for the Agent-Assisted Threat Detection Pipeline.

## Data Sources

### Input Data

#### PCAP Files
- **Format**: Standard PCAP or PCAPNG files
- **Source**: Network packet captures from:
  - Network taps
  - SPAN ports
  - Packet capture appliances
  - Security research datasets
- **Storage**: `data/raw/` directory (gitignored)
- **Size**: Variable (typically 10MB - 10GB)
- **Retention**: Not committed to version control (sensitive data)

#### Sample Data
- **Purpose**: Testing and development
- **Format**: Small PCAP files (< 10MB)
- **Sources**: Public datasets (e.g., CICIDS2017, UNSW-NB15)
- **Storage**: `tests/fixtures/` or `data/samples/` (if needed)

### Derived Data

#### Zeek Logs
- **Location**: `data/derived/zeek/`
- **Files**:
  - `conn.log`: Connection events (JSON format)
  - `dns.log`: DNS query/response events (JSON format)
- **Format**: JSON (one event per line)
- **Schema**: Zeek native schema (varies by log type)
- **Retention**: Generated per run, not committed to version control

#### Suricata Logs
- **Location**: `data/derived/suricata/`
- **Files**:
  - `eve.json`: Unified event log (JSON format)
- **Format**: JSON (one event per line)
- **Schema**: Suricata EVE JSON schema
- **Retention**: Generated per run, not committed to version control

### Normalized Data

#### Normalized Events (Parquet)
- **Location**: `reports/runs/<timestamp>/events.parquet`
- **Format**: Apache Parquet (columnar storage)
- **Schema**: Unified event schema (see below)
- **Retention**: Generated per run, included in run manifests

## Data Schemas

### Unified Event Schema

The normalized event schema unifies data from Zeek and Suricata:

```python
{
    "ts": float,              # Unix timestamp (seconds since epoch)
    "sensor": str,            # "zeek" or "suricata"
    "event_type": str,        # "conn", "dns", "flow", "alert", etc.
    "src_ip": str,            # Source IP address (IPv4 or IPv6)
    "dst_ip": str,            # Destination IP address
    "src_port": int,          # Source port (or None)
    "dst_port": int,          # Destination port (or None)
    "proto": str,             # Protocol ("tcp", "udp", "icmp", etc.)
    "uid": str,               # Zeek unique ID (or None for Suricata)
    "flow_id": int,           # Suricata flow ID (or None for Zeek)
    "severity": int,          # Alert severity (1-255, or None)
    "signature": str,         # Alert signature/rule name (or None)
    "metadata": str,          # JSON string with additional fields
    "case_id": str,           # Case ID (assigned during case assembly)
}
```

### Detection Schema

```python
{
    "detection_type": str,    # "recon_scanning" or "dns_beaconing"
    "ts": float,              # Detection timestamp
    "src_ip": str,            # Source IP address
    "dst_ip": str,            # Destination IP (or None for multiple)
    "confidence": float,      # Confidence score (0.0 - 1.0)
    "metadata": dict,         # Detection-specific metadata
}
```

### Case Schema

```python
{
    "case_id": str,           # Unique case identifier (e.g., "CASE_0001")
    "detection_type": str,    # Type of detection
    "src_ip": str,            # Source IP address
    "dst_ip": list,           # List of destination IPs (or empty)
    "domain": list,           # List of domains (for DNS cases)
    "ts_start": float,        # Case start timestamp
    "ts_end": float,          # Case end timestamp
    "detection_count": int,   # Number of detections in case
    "detections": list,       # List of detection dictionaries
    "evidence": list,         # List of evidence row dictionaries
    "validation": dict,       # CriticAgent validation results
    "report_content": str,    # Generated markdown report
}
```

### Run Manifest Schema

```json
{
    "run_timestamp": "20240101_120000",
    "pcap_file": "capture.pcap",
    "pcap_hash": "sha256:...",
    "git_commit": "abc123...",
    "git_branch": "main",
    "tool_versions": {
        "python": "3.11.0",
        "zeek": "6.0.0",
        "suricata": "7.0.0"
    },
    "config": {...},
    "outputs": {
        "events.parquet": "sha256:...",
        "case_report.md": "sha256:...",
        "agent_trace.jsonl": "sha256:..."
    }
}
```

## Data Processing Workflows

### Workflow 1: PCAP → Zeek Logs

```
PCAP File (data/raw/capture.pcap)
    ↓
[Docker: Zeek Service]
    ↓
Zeek Logs (data/derived/zeek/conn.log, dns.log)
```

**Processing Steps**:
1. Zeek reads PCAP file from mounted volume
2. Zeek processes packets and generates JSON logs
3. Logs written to `data/derived/zeek/`

**Configuration**: `configs/zeek/local.zeek`

### Workflow 2: PCAP → Suricata Logs

```
PCAP File (data/raw/capture.pcap)
    ↓
[Docker: Suricata Service]
    ↓
Suricata Logs (data/derived/suricata/eve.json)
```

**Processing Steps**:
1. Suricata reads PCAP file from mounted volume
2. Suricata processes packets and generates EVE JSON
3. Logs written to `data/derived/suricata/`

**Configuration**: `configs/suricata/suricata.yaml`

### Workflow 3: Logs → Normalized Events

```
Zeek Logs (conn.log, dns.log)
    ↓
[ZeekParser]
    ↓
Suricata Logs (eve.json)
    ↓
[SuricataParser]
    ↓
[EventNormalizer]
    ↓
Normalized Events (events.parquet)
```

**Processing Steps**:
1. Parse Zeek logs (JSON lines)
2. Parse Suricata logs (JSON lines)
3. Normalize to unified schema
4. Convert timestamps to Unix epoch
5. Map fields to unified schema
6. Write to Parquet format

**Output**: `reports/runs/<timestamp>/events.parquet`

### Workflow 4: Normalized Events → Detections

```
Normalized Events (events.parquet)
    ↓
[BaselineDetector]
    ├─→ Recon/Scanning Detection
    └─→ DNS Beaconing Detection
    ↓
Detections DataFrame
```

**Processing Steps**:
1. Load normalized events DataFrame
2. Apply recon/scanning algorithm:
   - Group by source IP and time window
   - Calculate fan-out (unique destinations)
   - Detect high fan-out thresholds
3. Apply DNS beaconing algorithm:
   - Group by source IP and domain
   - Calculate query frequency
   - Detect repeated queries
4. Output detections DataFrame

**Configuration**: `configs/detector.yaml`

### Workflow 5: Detections → Cases → Reports

```
Detections DataFrame
    ↓
[TriageAgent] → Group detections into cases
    ↓
[EvidenceAgent] → Retrieve supporting evidence
    ↓
[CriticAgent] → Validate case completeness
    ↓
[ReportAgent] → Generate markdown report
    ↓
Case Report (case_report.md)
```

**Processing Steps**:
1. TriageAgent groups detections by IP, time window, detection type
2. EvidenceAgent retrieves supporting rows from normalized events
3. CriticAgent validates evidence completeness
4. ReportAgent generates markdown report with:
   - Executive summary
   - Timeline
   - Evidence table
   - Confidence scores
   - Defensive recommendations

**Outputs**:
- `reports/runs/<timestamp>/case_report.md`
- `reports/runs/<timestamp>/agent_trace.jsonl`

## Data Quality and Validation

### Input Validation

- **PCAP Files**: Verify file exists and is readable
- **Log Files**: Handle missing or malformed log entries gracefully
- **Configuration**: Validate YAML syntax and required fields

### Processing Validation

- **Timestamp Parsing**: Handle multiple timestamp formats (ISO 8601, Unix epoch)
- **IP Address Validation**: Support IPv4 and IPv6
- **Port Validation**: Ensure ports are in valid range (1-65535)
- **Missing Fields**: Use None/null for missing optional fields

### Output Validation

- **Parquet Files**: Verify schema consistency
- **Case Reports**: Ensure all required sections present
- **Manifests**: Verify all hashes computed correctly

## Data Retention and Privacy

### Retention Policy

- **PCAP Files**: Not committed to version control (gitignored)
- **Derived Logs**: Generated per run, can be cleaned after analysis
- **Normalized Events**: Stored in timestamped run directories
- **Reports**: Retained for audit and analysis purposes

### Privacy Considerations

- **IP Addresses**: May contain sensitive internal IPs
- **Domains**: May reveal internal infrastructure
- **Timestamps**: May reveal operational patterns
- **Recommendation**: Review reports before sharing externally

### Data Handling Best Practices

1. **Never commit PCAP files** to version control
2. **Clean up derived logs** after analysis if required by policy
3. **Redact sensitive information** in reports if sharing externally
4. **Follow organization data retention policies**
5. **Use secure storage** for PCAP files (encrypted volumes)

## Data Flow Diagram

```
┌─────────────┐
│  PCAP File  │
└──────┬──────┘
       │
       ├─────────────────┐
       │                 │
       ▼                 ▼
┌──────────┐      ┌──────────────┐
│   Zeek   │      │  Suricata    │
└────┬─────┘      └──────┬───────┘
     │                   │
     ▼                   ▼
┌──────────┐      ┌──────────────┐
│ conn.log │      │   eve.json   │
│ dns.log  │      └──────┬───────┘
└────┬─────┘             │
     │                  │
     └────────┬─────────┘
              │
              ▼
     ┌─────────────────┐
     │ EventNormalizer │
     └────────┬────────┘
              │
              ▼
     ┌─────────────────┐
     │ events.parquet  │
     └────────┬────────┘
              │
              ▼
     ┌─────────────────┐
     │ BaselineDetector │
     └────────┬────────┘
              │
              ▼
     ┌─────────────────┐
     │   Detections    │
     └────────┬────────┘
              │
              ▼
     ┌─────────────────┐
     │ AgentOrchestrator│
     │  - TriageAgent   │
     │  - EvidenceAgent │
     │  - CriticAgent   │
     │  - ReportAgent   │
     └────────┬────────┘
              │
              ▼
     ┌─────────────────┐
     │  case_report.md │
     │ run_manifest.json│
     │ agent_trace.jsonl│
     └─────────────────┘
```

## Future Enhancements

### Data Sources (Post Week 2)

- **Firewall Logs**: Integrate firewall log parsing
- **Endpoint Logs**: Add endpoint telemetry (Sysmon, EDR)
- **Cloud Logs**: Support AWS CloudTrail, Azure logs
- **SIEM Integration**: Direct integration with Splunk, Elastic

### Schema Enhancements

- **Additional Fields**: User agents, file hashes, process names
- **Enrichment**: IP geolocation, domain reputation, threat intel
- **Relationships**: Graph-based event relationships

### Processing Enhancements

- **Streaming**: Real-time processing of live network traffic
- **Distributed**: Spark-based processing for large datasets
- **ML Features**: Feature engineering for machine learning models

---

**Version**: 1.0
**Last Updated**: [Current Date]
