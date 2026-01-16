#!/bin/bash
# Verify that a pipeline run completed successfully and all required outputs exist

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORTS_DIR="$REPO_ROOT/reports/runs"

# Find the latest run directory
if [ ! -d "$REPORTS_DIR" ]; then
    echo "Error: Reports directory does not exist: $REPORTS_DIR"
    exit 1
fi

# Check if directory is empty
if [ -z "$(ls -A $REPORTS_DIR 2>/dev/null)" ]; then
    echo "Error: No run directories found in $REPORTS_DIR"
    exit 1
fi

LATEST_RUN=$(ls -t "$REPORTS_DIR" 2>/dev/null | head -1)
if [ -z "$LATEST_RUN" ]; then
    echo "Error: Could not determine latest run directory"
    exit 1
fi
RUN_DIR="$REPORTS_DIR/$LATEST_RUN"

echo "Verifying run: $LATEST_RUN"
echo "Run directory: $RUN_DIR"
echo ""

ERRORS=0

# Check required files
check_file() {
    local file="$1"
    local description="$2"

    if [ ! -f "$file" ]; then
        echo "❌ Missing: $description"
        echo "   Expected: $file"
        ERRORS=$((ERRORS + 1))
        return 1
    fi

    if [ ! -s "$file" ]; then
        echo "⚠️  Empty: $description"
        echo "   File: $file"
        ERRORS=$((ERRORS + 1))
        return 1
    fi

    echo "✓ Found: $description"
    return 0
}

# Check run manifest
check_file "$RUN_DIR/run_manifest.json" "Run manifest"

# Check agent trace
check_file "$RUN_DIR/agent_trace.jsonl" "Agent trace"

# Check detections
check_file "$RUN_DIR/detections.jsonl" "Detections"

# Check case report
check_file "$RUN_DIR/case_report.md" "Case report"

# Check normalized events in run directory
check_file "$RUN_DIR/events.parquet" "Normalized events (run directory)"

# Check normalized events in data/normalized (optional, may have different naming)
NORMALIZED_DIR="$REPO_ROOT/data/normalized"
if [ -d "$NORMALIZED_DIR" ] && [ -n "$(ls -A $NORMALIZED_DIR/*.parquet 2>/dev/null)" ]; then
    PARQUET_COUNT=$(ls -1 "$NORMALIZED_DIR"/*.parquet 2>/dev/null | wc -l | tr -d ' ')
    echo "✓ Found $PARQUET_COUNT normalized event file(s) in data/normalized/"
else
    echo "⚠️  No normalized events found in data/normalized/ (optional)"
fi

# Check Zeek logs
ZEEK_DIR="$REPO_ROOT/data/derived/zeek"
if [ -f "$ZEEK_DIR/conn.log" ] || [ -f "$ZEEK_DIR/dns.log" ]; then
    echo "✓ Found Zeek logs in data/derived/zeek/"
else
    echo "⚠️  No Zeek logs found (may be empty or processing failed)"
fi

# Check Suricata logs
SURICATA_DIR="$REPO_ROOT/data/derived/suricata"
if [ -f "$SURICATA_DIR/eve.json" ]; then
    EVE_SIZE=$(stat -f%z "$SURICATA_DIR/eve.json" 2>/dev/null || stat -c%s "$SURICATA_DIR/eve.json" 2>/dev/null || echo "0")
    if [ "$EVE_SIZE" -gt 0 ]; then
        echo "✓ Found Suricata eve.json ($EVE_SIZE bytes)"
    else
        echo "⚠️  Suricata eve.json exists but is empty"
    fi
else
    echo "⚠️  No Suricata eve.json found (may be empty or processing failed)"
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ All required outputs verified successfully!"
    echo ""
    echo "Run summary:"
    echo "  - Manifest: $RUN_DIR/run_manifest.json"
    echo "  - Case Report: $RUN_DIR/case_report.md"
    echo "  - Detections: $RUN_DIR/detections.jsonl"
    echo "  - Agent Trace: $RUN_DIR/agent_trace.jsonl"
    echo "  - Events: $RUN_DIR/events.parquet"
    exit 0
else
    echo "❌ Verification failed with $ERRORS error(s)"
    exit 1
fi
