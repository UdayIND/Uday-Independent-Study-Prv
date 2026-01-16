# Docker Troubleshooting Guide

## Common Issues and Solutions

### Issue: Zeek/Suricata logs not generated

**Symptoms:**
- `data/derived/zeek/conn.log` is missing or empty
- `data/derived/suricata/eve.json` is missing or empty
- Pipeline reports 0 events parsed

**Solutions:**

1. **Verify Docker is running:**
   ```bash
   docker info
   ```

2. **Check Docker Compose configuration:**
   ```bash
   docker compose config
   ```

3. **Validate telemetry generation:**
   ```bash
   bash scripts/validate_telemetry.sh
   ```

4. **View Docker logs:**
   ```bash
   docker compose logs zeek
   docker compose logs suricata
   ```

5. **Clean rebuild:**
   ```bash
   make docker-rebuild
   ```

6. **Check directory permissions:**
   ```bash
   ls -la data/derived/zeek/
   ls -la data/derived/suricata/
   ```
   Containers run as `root` to ensure write access on Mac Docker Desktop.

7. **Verify PCAP file exists and is valid:**
   ```bash
   file data/raw/your_file.pcap
   ls -lh data/raw/
   ```

### Issue: Permission denied errors

**Symptoms:**
- Docker containers cannot write to mounted volumes
- Errors about read-only file system

**Solutions:**

- Containers run as `user: root` in `docker-compose.yml` for Mac compatibility
- Ensure directories exist before running:
  ```bash
  mkdir -p data/derived/zeek data/derived/suricata data/normalized reports/runs
  ```

### Issue: PCAP file not found in container

**Symptoms:**
- Error: "PCAP file /pcap/... not found"
- Zeek/Suricata exit immediately

**Solutions:**

1. **Verify PCAP_FILE environment variable:**
   ```bash
   export PCAP_FILE=your_file.pcap
   docker compose run --rm zeek
   ```

2. **Check volume mount:**
   ```bash
   docker compose config | grep -A 5 volumes
   ```

3. **Verify file exists on host:**
   ```bash
   ls -lh data/raw/your_file.pcap
   ```

### Issue: Zeek generates logs but they're empty

**Symptoms:**
- `conn.log` exists but has 0 lines (only headers)
- No actual event data

**Solutions:**

1. **PCAP may be empty or contain no network traffic:**
   ```bash
   tcpdump -r data/raw/your_file.pcap -c 10
   ```

2. **Try a different PCAP file:**
   ```bash
   bash scripts/download_sample_pcap.sh
   ```

3. **Check Zeek output format:**
   - Logs should be JSON format (configured in docker-compose.yml)
   - Verify with: `head -5 data/derived/zeek/conn.log`

### Issue: Suricata generates no alerts

**Symptoms:**
- `eve.json` exists but contains only flow events
- No alert events

**Solutions:**

1. **This is normal** - Suricata may not detect threats in benign traffic
2. **Check for flow events:**
   ```bash
   grep '"event_type":"flow"' data/derived/suricata/eve.json | wc -l
   ```
3. **Use a PCAP with known malicious traffic** for testing alerts

### Issue: Docker Compose version mismatch

**Symptoms:**
- Warning about obsolete `version` field
- Commands fail

**Solutions:**

- Use Docker Compose v2 (default in Docker Desktop)
- Command: `docker compose` (not `docker-compose`)
- Remove `version:` line from `docker-compose.yml` if present

### Issue: Containers exit immediately

**Symptoms:**
- Containers start and stop immediately
- No logs generated

**Solutions:**

1. **Check exit codes:**
   ```bash
   docker compose ps -a
   ```

2. **View container logs:**
   ```bash
   docker compose logs zeek
   docker compose logs suricata
   ```

3. **Run interactively for debugging:**
   ```bash
   docker compose run --rm zeek sh
   # Inside container:
   ls -la /pcap/
   zeek -r /pcap/your_file.pcap -C local
   ```

### Mac-Specific Issues

**File permissions:**
- Docker Desktop on Mac handles permissions differently
- Solution: Containers run as `root` user
- If issues persist, check Docker Desktop file sharing settings

**Volume mounts:**
- Use relative paths (e.g., `./data/raw`) in `docker-compose.yml`
- Docker Desktop resolves these relative to the compose file location

**Performance:**
- Large PCAPs may take time to process
- Monitor with: `docker stats`

## Quick Diagnostic Commands

```bash
# Check Docker status
docker info

# Check Docker Compose version
docker compose version

# Validate telemetry
bash scripts/validate_telemetry.sh

# View all container logs
docker compose logs

# Clean rebuild
make docker-rebuild

# Test Zeek directly
export PCAP_FILE=your_file.pcap
docker compose run --rm zeek

# Test Suricata directly
docker compose run --rm suricata

# Check generated files
ls -lh data/derived/zeek/
ls -lh data/derived/suricata/
```

## Getting Help

If issues persist:
1. Run `make preflight` to check prerequisites
2. Run `bash scripts/validate_telemetry.sh` to diagnose telemetry generation
3. Check `no_detections_diagnosis.md` if no detections are found
4. Review Docker logs: `docker compose logs zeek suricata`
