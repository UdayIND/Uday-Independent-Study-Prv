# Utility Scripts

This directory contains utility scripts for the SOC-Informed Discovery pipeline.

## Scripts

### `validate_pcap.py`

Validates a PCAP file before processing.

**Usage**:
```bash
python scripts/validate_pcap.py data/raw/capture.pcap
```

**Checks**:
- File exists
- File is not empty
- File extension is `.pcap` or `.pcapng`

---

More utility scripts will be added as needed.
