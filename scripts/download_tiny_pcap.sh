#!/bin/bash
# Download a very small PCAP sample for quick testing
# This is a minimal HTTP traffic capture suitable for fast pipeline runs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_RAW_DIR="$REPO_ROOT/data/raw"
PCAP_FILE="$DATA_RAW_DIR/tiny_sample.pcap"

# Create data/raw directory if it doesn't exist
mkdir -p "$DATA_RAW_DIR"

echo "Downloading tiny PCAP sample for quick testing..."

# Use a very small sample from a public PCAP repository
# Alternative: Use sample from Wireshark sample captures
TINY_URL="https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=http.cap"
# Fallback to a direct GitHub raw URL
FALLBACK_URL="https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures/http.cap"

if command -v curl &> /dev/null; then
    if curl -L -f -o "$PCAP_FILE" "$FALLBACK_URL" 2>/dev/null; then
        echo "✓ Downloaded from GitHub"
    elif curl -L -f -o "$PCAP_FILE" "$TINY_URL" 2>/dev/null; then
        echo "✓ Downloaded from Wireshark wiki"
    else
        echo "Error: Failed to download tiny PCAP sample from available sources"
        echo "Please manually download a small PCAP file and place it in: $DATA_RAW_DIR"
        echo "You can find sample PCAPs at: https://wiki.wireshark.org/SampleCaptures"
        exit 1
    fi
elif command -v wget &> /dev/null; then
    if wget -O "$PCAP_FILE" "$FALLBACK_URL" 2>/dev/null; then
        echo "✓ Downloaded from GitHub"
    elif wget -O "$PCAP_FILE" "$TINY_URL" 2>/dev/null; then
        echo "✓ Downloaded from Wireshark wiki"
    else
        echo "Error: Failed to download tiny PCAP sample from available sources"
        echo "Please manually download a small PCAP file and place it in: $DATA_RAW_DIR"
        echo "You can find sample PCAPs at: https://wiki.wireshark.org/SampleCaptures"
        exit 1
    fi
else
    echo "Error: Neither curl nor wget found. Please install one to download PCAP files."
    exit 1
fi

# Verify file was downloaded
if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file was not downloaded successfully"
    exit 1
fi

# Get file size
FILE_SIZE=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null || echo "unknown")
FILE_SIZE_KB=$(echo "scale=2; $FILE_SIZE / 1024" | bc 2>/dev/null || echo "unknown")

# Calculate SHA256 hash
if command -v shasum &> /dev/null; then
    SHA256=$(shasum -a 256 "$PCAP_FILE" | cut -d' ' -f1)
elif command -v sha256sum &> /dev/null; then
    SHA256=$(sha256sum "$PCAP_FILE" | cut -d' ' -f1)
else
    SHA256="unknown (shasum/sha256sum not found)"
fi

echo ""
echo "✓ Tiny PCAP file downloaded successfully!"
echo "  File: $PCAP_FILE"
echo "  Size: $FILE_SIZE bytes ($FILE_SIZE_KB KB)"
echo "  SHA256: $SHA256"
echo ""
echo "Note: This file is gitignored and will not be committed to the repository."
