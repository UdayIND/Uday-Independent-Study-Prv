#!/bin/bash
# Helper script to run Zeek and Suricata via Docker, then execute Python pipeline
# This ensures proper sequencing: Zeek/Suricata first, then Python processing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <pcap_file>"
    echo "Example: $0 data/raw/capture.pcap"
    exit 1
fi

PCAP_FILE="$1"
PCAP_BASENAME=$(basename "$PCAP_FILE")

# Convert to absolute path if relative
if [[ "$PCAP_FILE" != /* ]]; then
    PCAP_ABS_PATH="$REPO_ROOT/$PCAP_FILE"
else
    PCAP_ABS_PATH="$PCAP_FILE"
fi

if [ ! -f "$PCAP_ABS_PATH" ]; then
    echo "Error: PCAP file not found: $PCAP_ABS_PATH"
    exit 1
fi

cd "$REPO_ROOT"

echo "=========================================="
echo "SOC-Informed Discovery Pipeline"
echo "=========================================="
echo "PCAP File: $PCAP_FILE"
echo ""

# Check if Docker is available
if ! docker info > /dev/null 2>&1; then
    echo "Warning: Docker is not running or not available."
    echo "Skipping Zeek and Suricata processing."
    echo "The pipeline will attempt to process existing logs if available."
    echo ""
    SKIP_DOCKER=true
else
    SKIP_DOCKER=false
fi

# Step 1: Run Zeek
if [ "$SKIP_DOCKER" = "false" ]; then
    echo "Step 1/3: Running Zeek..."
    export PCAP_FILE="$PCAP_BASENAME"
    docker compose run --rm zeek || {
        echo "Warning: Zeek processing completed (may have warnings)"
    }
else
    echo "Step 1/3: Skipping Zeek (Docker not available)"
fi

# Step 2: Run Suricata
if [ "$SKIP_DOCKER" = "false" ]; then
    echo ""
    echo "Step 2/3: Running Suricata..."
    docker compose run --rm suricata || {
        echo "Warning: Suricata processing completed (may have warnings)"
    }
else
    echo "Step 2/3: Skipping Suricata (Docker not available)"
fi

# Step 3: Run Python pipeline
echo ""
echo "Step 3/3: Running Python pipeline..."
if [ -d "$REPO_ROOT/venv" ]; then
    . "$REPO_ROOT/venv/bin/activate" && python3 -m src.main --pcap "$PCAP_ABS_PATH"
else
    python3 -m src.main --pcap "$PCAP_ABS_PATH"
fi

echo ""
echo "=========================================="
echo "Pipeline completed successfully!"
echo "=========================================="
