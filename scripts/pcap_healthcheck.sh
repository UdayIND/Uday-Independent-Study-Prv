#!/bin/bash
# Validate that a file is a valid PCAP file

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <pcap_file>"
    echo "Validates that a file is a valid PCAP file"
    exit 1
fi

PCAP_FILE="$1"
MIN_SIZE_KB=${2:-50}  # Default minimum size: 50KB

if [ ! -f "$PCAP_FILE" ]; then
    echo "❌ Error: File not found: $PCAP_FILE"
    exit 1
fi

# Check file type
FILE_TYPE=$(file "$PCAP_FILE" 2>/dev/null || echo "unknown")
FILE_SIZE=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null || echo "0")
FILE_SIZE_KB=$((FILE_SIZE / 1024))

# Validate file type
if ! echo "$FILE_TYPE" | grep -qiE "pcap|tcpdump|capture|data"; then
    echo "❌ Invalid PCAP file: $PCAP_FILE"
    echo "   File type: $FILE_TYPE"
    echo "   Expected: PCAP/TCPDUMP format"
    echo ""
    echo "Remediation steps:"
    echo "1. Verify the file was downloaded correctly"
    echo "2. Try downloading from a different source"
    echo "3. Check if the URL redirects to HTML instead of binary data"
    echo "4. Manually download a PCAP file and place it in data/raw/"
    exit 1
fi

# Validate file size
if [ "$FILE_SIZE_KB" -lt "$MIN_SIZE_KB" ]; then
    echo "⚠️  Warning: PCAP file is very small: $FILE_SIZE_KB KB (minimum recommended: $MIN_SIZE_KB KB)"
    echo "   File: $PCAP_FILE"
    echo "   This may indicate an incomplete download or empty capture"
    echo ""
    echo "Remediation steps:"
    echo "1. Re-download the file"
    echo "2. Try a different PCAP source"
    echo "3. Verify the file contains actual network traffic"
    # Don't exit with error for small files, just warn
fi

# Check for HTML content (common issue with redirects)
if head -1 "$PCAP_FILE" 2>/dev/null | grep -qiE "<!doctype|<html|<head"; then
    echo "❌ Invalid PCAP file: $PCAP_FILE"
    echo "   File appears to be HTML (likely a redirect page)"
    echo "   File type: $FILE_TYPE"
    echo ""
    echo "Remediation steps:"
    echo "1. The download URL likely redirected to an HTML page"
    echo "2. Try downloading from a different source"
    echo "3. Use a direct download link that returns binary data"
    echo "4. Manually download a PCAP file and place it in data/raw/"
    exit 1
fi

# Success
echo "✓ Valid PCAP file: $PCAP_FILE"
echo "   File type: $FILE_TYPE"
echo "   Size: $FILE_SIZE bytes ($FILE_SIZE_KB KB)"
exit 0
