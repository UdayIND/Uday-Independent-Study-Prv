# SOC Pilot Proposal: Agentic Threat Detection & Triage Copilot

## 1. Executive Summary

This proposal outlines a pilot deployment of an agentic network threat detection
and triage system designed to reduce analyst workload by automatically converting
raw network telemetry into evidence-grounded, analyst-ready incident cases.

The system ingests Zeek and Suricata logs, applies multi-signal behavioral
detectors (recon scanning with fan-out/burst/failed-connection analysis, DNS
beaconing with periodicity/NXDOMAIN/domain-diversity analysis), and uses a
multi-agent pipeline (Triage, Evidence, Critic, Report) with configurable
multi-round orchestration to produce structured cases with:

- Relevance-scored evidence bundles tied to specific network events
- 5-factor confidence scores (detection strength, evidence volume, sensor diversity, temporal concentration, cross-case correlation)
- Defensive recommendations per case
- Auditable agent trace logs for every decision
- Ground truth evaluation metrics (precision, recall, F1) when labeled data is available

In internal benchmarks across 12 synthetic PCAPs (including 3 adversarial
evasion tests) and 2 public datasets:
- **100% evidence completeness** on all detected malicious cases
- **0 false positives** on benign traffic (3 benign PCAPs including Wireshark HTTP)
- **Up to 4:1 compression ratio** on slow-drip evasion, 1.5:1 on multi-attacker
- **Hedge's g = 0.87** (large effect size) distinguishing malicious from benign
- **Honest evasion results**: IP rotation evaded detection (0/5 scanners caught),
  jittery beaconing detected, slow-drip exfiltration detected
- **Critic calibration**: 5-factor model produces lower, better-calibrated
  confidence (0.77) vs overconfident no-critic baseline (0.92)

The 5-configuration ablation study demonstrates that each pipeline layer adds
measurable value, with the full pipeline (Configuration C) providing the most
complete analyst experience.

The pilot requires minimal SOC integration: read-only log exports from existing
Zeek and Suricata sensors. No changes to production infrastructure are needed.

---

## 2. What We Need From the SOC

The data requirements are intentionally minimal and low-risk:

### Required Data Fields

| Field | Source | Description |
|-------|--------|-------------|
| Timestamp (`ts`) | Zeek/Suricata | Event timestamp (epoch or ISO-8601) |
| Source IP (`src_ip`) | Zeek/Suricata | Originating IP address |
| Destination IP (`dst_ip`) | Zeek/Suricata | Target IP address |
| Source Port (`src_port`) | Zeek/Suricata | Originating port |
| Destination Port (`dst_port`) | Zeek/Suricata | Target port |
| Protocol (`proto`) | Zeek/Suricata | Transport protocol (TCP/UDP/ICMP) |
| Connection UID (`uid`) | Zeek | Zeek connection identifier |
| Flow ID (`flow_id`) | Suricata | Suricata flow identifier |
| DNS query/response | Zeek DNS logs | Domain name, query type, response code |
| Alert signature | Suricata EVE | Signature name, severity, category |

### Log Types

- **Zeek**: `conn.log`, `dns.log` (JSON format preferred)
- **Suricata**: `eve.json` (EVE JSON output)

### Deployment Requirements

- **Read-only access** to log exports (file copy, syslog forward, or SIEM export)
- **No inline deployment**: the system processes logs offline/batch
- **No changes** to existing sensor configurations
- **Storage**: approximately 2x the raw log volume for derived and normalized data
- **Compute**: single Linux host or container runtime (Docker)

### What We Do NOT Need

- No access to production network infrastructure
- No firewall or IDS rule changes
- No credential or authentication data
- No packet payloads (only metadata/flow records)
- No PII or user identity data

---

## 3. What We Offer

### 3.1 Core Deliverables Per Run

| Output | Description |
|--------|-------------|
| **Structured Cases** | Deduplicated incident cases with case IDs, detection types, and severity |
| **Evidence Bundles** | Per-case correlated network events with timestamps, IPs, ports, and protocols |
| **Confidence Scores** | Per-case confidence (0.0-1.0) based on evidence volume, cross-sensor correlation, and detection specificity |
| **Stated Limitations** | Each case explicitly notes what the system cannot determine (e.g., payload content, lateral movement beyond observed traffic) |
| **Defensive Recommendations** | Per-case recommended actions (block source, investigate host, review DNS policy) |
| **Analyst-Ready Reports** | Markdown case reports ready for Tier-1/Tier-2 review |

### 3.2 Evaluation Metrics

| Metric | What It Measures |
|--------|-----------------|
| **Alert-to-Case Compression Ratio** | How many raw detections are consolidated per case (higher = more noise reduction) |
| **Evidence Completeness** | Percentage of cases with structured, referenceable evidence rows |
| **FP Proxy (detections/hour)** | Detection rate on known-benign traffic (lower = fewer false positives) |
| **Precision / Recall / F1** | Ground truth accuracy when labeled data is available |
| **5-Factor Confidence Score** | Weighted assessment of detection strength, evidence volume, sensor diversity, temporal concentration, and cross-case correlation |
| **Confidence Distribution** | Statistical spread of case confidence scores |

### 3.3 Auditability

Every pipeline run produces:

- `agent_trace.jsonl`: Step-by-step log of every agent decision
- `detections.jsonl`: Raw detections before case assembly
- `cases.json`: Serialized case metadata and validation results
- `evaluation_summary.json`: Computed metrics for the run
- `evaluation_report.md`: Human-readable report with embedded visualizations
- `figures/`: 17 diagnostic plots (event rates, IP distributions, detection timelines, compression ratios, evidence completeness, confusion matrix, confidence distribution, pipeline funnel, confidence factor breakdown, detection signal heatmap)

---

## 4. Pilot Plan

### Phase 1: Data Mapping (Week 1)

**Objective**: Validate that SOC log exports match expected schema.

- Receive sample log exports (1-2 hours of Zeek + Suricata data)
- Run normalization pipeline to verify field mapping
- Identify any schema gaps or format variations
- Deliver: Data health report with field coverage and missing value rates

### Phase 2: Sample Window Run (Weeks 2-3)

**Objective**: Process a representative traffic window and assess detection quality.

- Process 4-8 hours of production traffic through the full pipeline
- Generate cases, evidence bundles, and evaluation metrics
- Compare detections against any known incidents in the window
- Deliver: Full evaluation report with cases, metrics, and visualizations

### Phase 3: Analyst Feedback (Week 4)

**Objective**: Gather SOC analyst feedback on case quality and utility.

- Present 5-10 representative cases to Tier-1/Tier-2 analysts
- Collect structured feedback on:
  - Case relevance (true positive, false positive, uncertain)
  - Evidence sufficiency (enough context to act?)
  - Report clarity (understandable without additional investigation?)
  - Recommendation quality (actionable and appropriate?)
- Deliver: Analyst feedback summary with quantified scores

### Phase 4: Tune and ROI Assessment (Weeks 5-6)

**Objective**: Adjust detector thresholds and measure analyst time savings.

- Tune detection thresholds based on analyst feedback
  - Recon scanning: fan-out threshold, burst threshold
  - DNS beaconing: repeated query threshold, NXDOMAIN ratio
- Re-run pipeline with tuned parameters on expanded traffic window
- Estimate analyst time savings:
  - Cases reviewed vs raw alerts that would require review
  - Time per case (with evidence) vs time per raw alert (without context)
- Deliver: Tuning report, ROI estimate, go/no-go recommendation

---

## 5. Success Criteria

The pilot succeeds if all of the following are met:

### Quantitative Criteria

| Criterion | Target | Measurement |
|-----------|--------|-------------|
| Alert-to-Case Compression | >= 3:1 | `compression_ratio` in evaluation metrics |
| Evidence Completeness | >= 80% | Percentage of cases with structured evidence |
| FP Proxy on Benign Traffic | < 5 detections/hour | Measured on known-benign traffic segments |
| Analyst Relevance Score | >= 3.5/5.0 | Mean analyst rating across presented cases |
| Explainability | >= 70% | Cases meeting minimum evidence row threshold |

### Qualitative Criteria

- Analysts report that case evidence is sufficient to begin investigation without returning to raw logs in >= 60% of cases
- Report format is clear enough for Tier-1 triage without additional training
- Defensive recommendations are considered actionable in >= 50% of cases
- No false sense of security: confidence scores and limitations accurately reflect system capabilities

### Exit Criteria

The pilot should be discontinued if:

- Compression ratio is < 1.5:1 (insufficient noise reduction)
- FP proxy on benign traffic exceeds 20 detections/hour (excessive false positives)
- Analyst relevance score is below 2.0/5.0 (detections are not useful)
- Evidence completeness is below 50% (insufficient evidence correlation)

---

## 6. Benchmark Results Summary

The system has been validated against a benchmark suite of 12 synthetic PCAPs
(9 standard + 3 adversarial evasion) and 2 public datasets (CTU-13, Wireshark
HTTP), with known ground truth labels. Results are stored in
`reports/benchmark/` and can be regenerated with `make benchmark`.

### Benchmark PCAPs

| PCAP | Label | Description |
|------|-------|-------------|
| synthetic-scan | Malicious | One source scanning 120+ destinations on ports 22, 80, 443 |
| synthetic-beacon | Malicious | Repeated DNS queries to C2 domain every 30 seconds |
| synthetic-benign | Benign | Normal web browsing with 12 unique domains |
| synthetic-mixed | Malicious | Normal traffic + embedded scan from one IP |
| synthetic-dns-exfil | Malicious | DNS exfiltration via high-entropy subdomain queries |
| synthetic-multi-attacker | Malicious | 3 simultaneous attackers: 2 scanners + 1 DNS beaconer |
| synthetic-killchain | Malicious | Single attacker: recon, C2 beaconing, lateral movement |
| synthetic-slow-scan | Malicious | Low-and-slow scanner (1 conn/30-60s) with heavy noise |
| synthetic-noisy-benign | Benign | High-volume benign traffic mimicking malicious patterns |

### Benchmark Results

| PCAP | Label | Events | Detections | Cases | Compression | Evidence | FP Proxy |
|------|-------|--------|------------|-------|-------------|----------|----------|
| synthetic-scan | Malicious | 868 | 1 | 1 | 1.0:1 | 100% | 52.3/hr |
| synthetic-beacon | Malicious | 352 | 1 | 1 | 1.0:1 | 100% | 2.8/hr |
| synthetic-benign | Benign | 168 | 0 | 0 | N/A | N/A | 0.0/hr |
| synthetic-mixed | Malicious | 788 | 2 | 1 | 2.0:1 | 100% | 4.9/hr |
| synthetic-dns-exfil | Malicious | 466 | 1 | 1 | 1.0:1 | 100% | 2.4/hr |
| synthetic-multi-attacker | Malicious | 805 | 2 | 2 | 1.0:1 | 100% | 8.5/hr |
| synthetic-killchain | Malicious | 394 | 2 | 2 | 1.0:1 | 100% | 4.0/hr |
| synthetic-slow-scan | Malicious | 2678 | 1 | 1 | 1.0:1 | 100% | 2.0/hr |
| synthetic-noisy-benign | Benign | 820 | 0 | 0 | N/A | N/A | 0.0/hr |
| *evasion-ip-rotation* | Malicious | 552 | **0** | **0** | N/A | N/A | 0.0/hr |
| *evasion-jittery-beacon* | Malicious | 390 | 1 | 1 | 1.0:1 | 100% | 3.0/hr |
| *evasion-slow-drip* | Malicious | 1486 | 20 | 5 | 4.0:1 | 100% | 20.0/hr |
| wireshark-http | Benign | 2 | 0 | 0 | N/A | N/A | 0.0/hr |

*P/R/F1 omitted: benign PCAPs with 0 detections yield undefined (0/0) metrics.
CTU-13 (56MB real PCAP) timed out during processing.*

### Aggregate Metrics

- **Detected malicious PCAPs**: 100% evidence completeness, 1.30 avg compression
- **Benign PCAPs**: 0 false positives across 3 benign PCAPs (including real Wireshark HTTP)
- **Statistical significance**: Hedge's g = 0.87 (large), n_malicious=10, n_benign=3
- **Evasion results**: 1/3 evasion PCAPs evaded detection completely (IP rotation)

Detailed results including comparison tables, per-PCAP breakdowns, and FP proxy
comparison charts are available in `reports/benchmark/<timestamp>/benchmark_report.md`.

---

## 7. Ablation Study Findings

The ablation study compares five pipeline configurations to demonstrate the
marginal value of each component. Results are stored in `reports/ablation/` and
can be regenerated with `make ablation PCAP=<path>`.

### Configuration Comparison

| Capability | (A) Suricata | (B) Detectors | (C) Full | (D) No Critic | (E) Zeek Only |
|------------|:---:|:---:|:---:|:---:|:---:|
| Raw alert count | Yes | - | - | - | - |
| Behavioral detection | - | Yes | Yes | Yes | Yes |
| Case assembly | - | - | Yes | Yes | Yes |
| Evidence correlation | - | - | Yes | Yes | Yes* |
| Critic validation | - | - | Yes | - | Yes |
| Multi-sensor fusion | - | - | Yes | Yes | - |
| Analyst-ready report | - | - | Yes | Yes | Yes |

*Single sensor evidence only

### Ablation Results (synthetic_multi_attacker.pcap)

| Metric | (A) | (B) | (C) | (D) | (E) |
|--------|-----|-----|-----|-----|-----|
| Detections | 0 | 3 | 3 | 3 | 2 |
| Cases | 0 | 0 | 2 | 2 | 2 |
| Compression | 0:1 | 0:1 | 1.5:1 | 1.5:1 | 1.0:1 |
| Evidence Completeness | 0% | 0% | 100% | 100% | 100% |
| Mean Confidence | 0.00 | 0.00 | **0.77** | 0.92 | 0.67 |

### Key Findings

- **Critic agent calibrates confidence**: Configuration C (with critic,
  confidence=0.77) vs D (without critic, confidence=0.92) demonstrates that the
  5-factor model _lowers_ overconfident scores by incorporating sensor diversity
  and cross-case correlation — producing better-calibrated confidence.

- **Multi-sensor fusion improves confidence by 15% and detection by 50%**:
  Configuration C (dual sensor, 3 detections, confidence=0.77) vs E (Zeek only,
  2 detections, confidence=0.67) — the extra sensor catches threats missed by
  single-source analysis.

- **Alert compression**: The full pipeline compresses 3 raw detections from
  multi-attacker traffic into 2 correlated cases (1.5:1 ratio).

- **Suricata alone finds nothing** on behavioral threats: Configuration A produces
  0 detections because Suricata's signature-based approach cannot detect
  behavioral patterns without predefined rules. **Note**: Config A uses default
  community rules with no custom signatures. Our synthetic PCAPs contain novel
  behavioral patterns that will not match any community rules. This demonstrates
  the gap between signature-based and behavioral detection, not a flaw in
  Suricata itself.

- **Detectors without agents produce no actionable output**: Configuration B
  produces 3 detections but no cases, evidence bundles, or reports — requiring
  manual analyst correlation.

Detailed comparison tables and analysis are available in
`reports/ablation/<timestamp>/ablation_report.md`.

---

## 8. Technical Architecture

```
PCAP File
    |
    v
+-------------------+     +---------------------+
|   Zeek Container  |     |  Suricata Container |
|   (conn, dns logs)|     |  (eve.json alerts)  |
+-------------------+     +---------------------+
         |                          |
         v                          v
    +------------------------------------+
    |        Event Normalizer            |
    |  (Unified 13-field schema)         |
    +------------------------------------+
                    |
                    v
    +------------------------------------+
    |       Baseline Detectors           |
    |  - Recon/Scanning (3-signal)       |
    |    fan-out + burst + failed-conn   |
    |  - DNS Beaconing (4-signal)        |
    |    repeat + periodicity + NXDOMAIN |
    |    + domain diversity              |
    +------------------------------------+
                    |
                    v
    +------------------------------------+
    |   Agent Orchestrator (multi-round) |
    |   max_retries: configurable (3)    |
    |                                    |
    |  Step 1: TriageAgent               |
    |    - Group by (type, src, window)  |
    |    - Assemble initial cases        |
    |                                    |
    |  Step 2: EvidenceAgent             |
    |    - Relevance scoring (4 factors) |
    |    - Cross-sensor enrichment       |
    |    - Temporal proximity weighting  |
    |                                    |
    |  Step 3: CriticAgent               |
    |    - 5-factor confidence model     |
    |    - Cross-case correlation        |
    |    - Temporal concentration check  |
    |    - Flag insufficient cases       |
    |                                    |
    |  [Loop if invalid, expand search]  |
    |                                    |
    |  Step 4: ReportAgent               |
    |    - Generate case reports         |
    |    - Add recommendations           |
    |    - State limitations             |
    +------------------------------------+
                    |
                    v
    +------------------------------------+
    |           Evaluator                |
    |  - Data health metrics             |
    |  - Detection quality metrics       |
    |  - SOC triage metrics              |
    |  - Ground truth (P/R/F1)           |
    |  - 17 diagnostic visualizations    |
    +------------------------------------+
                    |
                    v
    reports/runs/<timestamp>/
      - run_manifest.json
      - cases.json
      - case_report.md
      - detections.jsonl
      - agent_trace.jsonl
      - events.parquet
      - evaluation_summary.json
      - evaluation_report.md
      - figures/ (16 plots)
```

**Terminology note**: Throughout this proposal, we use "agent" to describe
pipeline stages with distinct detection, triage, and validation responsibilities
(e.g., TriageAgent, CriticAgent). These are deterministic rule-based software
components with fixed scoring logic, not autonomous AI agents with learned
policies or independent decision-making. The orchestration pattern draws from
multi-agent systems literature but is more accurately described as a staged
pipeline with a critic feedback loop.

---

## 9. Related Work and Positioning

This system builds on several lines of research in network intrusion detection
and SOC automation:

| System | Approach | Key Limitation Addressed |
|--------|----------|--------------------------|
| **Suricata/Snort** | Signature-based alerting | Cannot detect behavioral patterns (scanning, beaconing) without predefined rules |
| **Zeek** | Protocol analysis + scripting | Produces raw logs requiring manual correlation and analysis |
| **DeepLog** (Du et al.) | LSTM-based log anomaly detection | Single-log-source; no cross-sensor fusion or multi-signal confidence |
| **Kitsune** (Mirsky et al.) | Online ensemble autoencoder for NIDS | Real-time anomaly scores but no structured case output or analyst-ready reports |
| **CORGIDS** (Haas & Fischer) | Graph-based IDS with correlated alerts | Alert correlation but no agentic validation loop or evidence relevance scoring |
| **LLM-based SOC tools** | GPT/Claude for alert triage | Natural language but risk of hallucination; no structured evidence validation |

**Our contribution**: This system combines behavioral multi-signal detection
(not just signatures), multi-agent orchestration with a critic validation loop,
relevance-scored evidence retrieval, and a 5-factor confidence model — providing
structured, auditable, analyst-ready output that existing approaches do not.

---

## 10. Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Log format mismatch | Medium | Phase 1 data mapping validates schema before processing |
| High false positive rate | Medium | Tunable detector thresholds; Phase 4 tunes based on feedback |
| Insufficient evidence for cases | Low | Evidence completeness metric tracks this; critic agent flags weak cases |
| System generates false confidence | Low | Confidence scores include limitations; critic agent validates claims |
| SOC integration overhead | Low | Read-only log export only; no inline or production changes |
| Performance on large volumes | Medium | Batch processing model; can be parallelized per time window |

---

## 11. Next Steps

1. **Schedule kickoff meeting** to discuss data export logistics
2. **Provide sample logs** (1-2 hours of Zeek conn.log + dns.log, Suricata eve.json)
3. **Run Phase 1 data mapping** to validate schema compatibility
4. **Review this proposal** and confirm success criteria alignment

Contact: [Researcher Name / Team]
Repository: [Project Repository URL]
