#!/bin/bash
# Download a reliable sample PCAP file for testing
# Uses multiple fallback sources with validation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_RAW_DIR="$REPO_ROOT/data/raw"
PCAP_FILE="$DATA_RAW_DIR/sample.pcap"
HEALTHCHECK_SCRIPT="$SCRIPT_DIR/pcap_healthcheck.sh"

# Create data/raw directory if it doesn't exist
mkdir -p "$DATA_RAW_DIR"

# PCAP sources (ordered by preference)
# 1. Wireshark sample captures (direct GitHub raw links) - preferred
# 2. Public malware traffic samples
# 3. Alternative PCAP repositories

declare -a PCAP_URLS=(
    # Wireshark sample captures (direct GitHub raw links)
    "https://github.com/wireshark/wireshark/raw/master/test/captures/dhcp.pcap"

    # Alternative Wireshark samples
    "https://github.com/wireshark/wireshark/raw/master/test/captures/http.pcap"

    # Another Wireshark sample
    "https://github.com/wireshark/wireshark/raw/master/test/captures/sip.pcap"
)

# Function to download and validate PCAP
download_and_validate() {
    local url="$1"
    local output_file="$2"

    echo "Attempting download from: $url"

    # Download
    if command -v curl &> /dev/null; then
        if ! curl -L -f -o "$output_file" "$url" 2>/dev/null; then
            return 1
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -O "$output_file" "$url" 2>/dev/null; then
            return 1
        fi
    else
        echo "Error: Neither curl nor wget found"
        return 1
    fi

    # Validate using healthcheck script
    if [ -f "$HEALTHCHECK_SCRIPT" ]; then
        if bash "$HEALTHCHECK_SCRIPT" "$output_file" 50 > /dev/null 2>&1; then
            return 0
        else
            # Healthcheck failed, remove invalid file
            rm -f "$output_file"
            return 1
        fi
    else
        # Fallback validation if healthcheck script doesn't exist
        FILE_TYPE=$(file "$output_file" 2>/dev/null || echo "unknown")
        if echo "$FILE_TYPE" | grep -qiE "pcap|tcpdump|capture|data"; then
            # Check for HTML content
            if head -1 "$output_file" 2>/dev/null | grep -qiE "<!doctype|<html|<head"; then
                rm -f "$output_file"
                return 1
            fi
            return 0
        else
            rm -f "$output_file"
            return 1
        fi
    fi
}

echo "Downloading sample PCAP file..."
echo ""

# Try each URL until one succeeds
DOWNLOADED=false
USED_URL=""

for url in "${PCAP_URLS[@]}"; do
    if download_and_validate "$url" "$PCAP_FILE"; then
        DOWNLOADED=true
        USED_URL="$url"
        break
    else
        echo "  ✗ Download failed or validation failed, trying next source..."
        echo ""
    fi
done

if [ "$DOWNLOADED" = false ]; then
    echo "❌ Error: Failed to download a valid PCAP from all sources"
    echo ""
    echo "Please manually download a PCAP file and place it in: $DATA_RAW_DIR"
    echo "Recommended sources:"
    echo "  - CTU-13 Dataset: https://www.stratosphereips.org/datasets-ctu13"
    echo "  - Wireshark Sample Captures: https://wiki.wireshark.org/SampleCaptures"
    echo "  - Malware Traffic Analysis: https://www.malware-traffic-analysis.net/"
    exit 1
fi

# Get file info
FILE_SIZE=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null || echo "unknown")
FILE_SIZE_MB=$(echo "scale=2; $FILE_SIZE / 1024 / 1024" | bc 2>/dev/null || echo "unknown")
FILE_TYPE=$(file "$PCAP_FILE" 2>/dev/null || echo "unknown")

# Calculate SHA256 hash
if command -v shasum &> /dev/null; then
    SHA256=$(shasum -a 256 "$PCAP_FILE" | cut -d' ' -f1)
elif command -v sha256sum &> /dev/null; then
    SHA256=$(sha256sum "$PCAP_FILE" | cut -d' ' -f1)
else
    SHA256="unknown (shasum/sha256sum not found)"
fi

echo "✓ PCAP file downloaded and validated successfully!"
echo ""
echo "  File: $PCAP_FILE"
echo "  Source URL: $USED_URL"
echo "  Size: $FILE_SIZE bytes ($FILE_SIZE_MB MB)"
echo "  SHA256: $SHA256"
echo "  File type: $FILE_TYPE"
echo ""
echo "Note: This file is gitignored and will not be committed to the repository."
