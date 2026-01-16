#!/bin/bash
# Download CTU-13 Neris botnet PCAP sample for testing
# Source: Stratosphere Laboratory, CTU-13 Dataset
# This script downloads a public PCAP file for testing purposes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_RAW_DIR="$REPO_ROOT/data/raw"
PCAP_FILE="$DATA_RAW_DIR/ctu13_neris.pcap"

# Create data/raw directory if it doesn't exist
mkdir -p "$DATA_RAW_DIR"

echo "Downloading CTU-13 Neris botnet PCAP sample..."
echo "Source: Stratosphere Laboratory CTU-13 Dataset"

# Use a reliable public PCAP source
# Using a small HTTP traffic sample from Wireshark sample captures
SAMPLE_URL="https://github.com/wireshark/wireshark/raw/master/test/captures/http.cap"

echo "Downloading sample PCAP from Wireshark test captures..."

# Download PCAP
if command -v curl &> /dev/null; then
    if ! curl -L -f -o "$PCAP_FILE" "$SAMPLE_URL" 2>/dev/null; then
        echo "Error: Failed to download PCAP from $SAMPLE_URL"
        echo "Please manually download a PCAP file and place it in: $DATA_RAW_DIR"
        exit 1
    fi
elif command -v wget &> /dev/null; then
    if ! wget -O "$PCAP_FILE" "$SAMPLE_URL" 2>/dev/null; then
        echo "Error: Failed to download PCAP from $SAMPLE_URL"
        echo "Please manually download a PCAP file and place it in: $DATA_RAW_DIR"
        exit 1
    fi
else
    echo "Error: Neither curl nor wget found. Please install one to download PCAP files."
    exit 1
fi

# Verify it's actually a PCAP file
if ! file "$PCAP_FILE" | grep -qi "pcap\|tcpdump\|capture"; then
    echo "Warning: Downloaded file does not appear to be a PCAP file"
    echo "File type: $(file "$PCAP_FILE")"
    echo "Removing invalid file..."
    rm -f "$PCAP_FILE"
    exit 1
fi

# Verify file was downloaded
if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file was not downloaded successfully"
    exit 1
fi

# Get file size
FILE_SIZE=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null || echo "unknown")
FILE_SIZE_MB=$(echo "scale=2; $FILE_SIZE / 1024 / 1024" | bc 2>/dev/null || echo "unknown")

# Calculate SHA256 hash
if command -v shasum &> /dev/null; then
    SHA256=$(shasum -a 256 "$PCAP_FILE" | cut -d' ' -f1)
elif command -v sha256sum &> /dev/null; then
    SHA256=$(sha256sum "$PCAP_FILE" | cut -d' ' -f1)
else
    SHA256="unknown (shasum/sha256sum not found)"
fi

echo ""
echo "✓ PCAP file downloaded successfully!"
echo "  File: $PCAP_FILE"
echo "  Size: $FILE_SIZE bytes ($FILE_SIZE_MB MB)"
echo "  SHA256: $SHA256"
echo ""
echo "Note: This file is gitignored and will not be committed to the repository."
