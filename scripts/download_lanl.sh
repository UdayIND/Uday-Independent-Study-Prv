#!/usr/bin/env bash
# =============================================================================
# Download LANL Comprehensive, Multi-Source Cyber-Security Events Dataset
# Reference: https://csr.lanl.gov/data/cyber1/
# Kent, A.D. (2015). "Comprehensive, Multi-Source Cyber-Security Events"
#
# NOTE: The LANL dataset requires agreeing to their terms of use.
# This script downloads the auth.txt.gz file (~1.5 GB compressed).
# =============================================================================

set -euo pipefail

DATA_DIR="${1:-data/lanl}"
BASE_URL="https://csr.lanl.gov/data/cyber1"

mkdir -p "$DATA_DIR"

echo "============================================"
echo "SENTINEL-RL: LANL Dataset Download"
echo "============================================"
echo ""
echo "Target directory: $DATA_DIR"
echo ""

# Download auth.txt.gz (primary dataset for the paper)
AUTH_FILE="$DATA_DIR/auth.txt.gz"
AUTH_TXT="$DATA_DIR/auth.txt"

if [ -f "$AUTH_TXT" ]; then
    echo "✅ auth.txt already exists ($AUTH_TXT). Skipping download."
else
    echo "Downloading auth.txt.gz (~1.5 GB)..."
    echo "  Source: $BASE_URL/auth.txt.gz"
    echo ""
    echo "⚠️  NOTE: You may need to manually download from:"
    echo "    https://csr.lanl.gov/data/cyber1/"
    echo "   and accept the LANL terms of use."
    echo ""

    if command -v wget &>/dev/null; then
        wget -c "$BASE_URL/auth.txt.gz" -O "$AUTH_FILE" || {
            echo "❌ Download failed. Please download manually."
            exit 1
        }
    elif command -v curl &>/dev/null; then
        curl -L -C - "$BASE_URL/auth.txt.gz" -o "$AUTH_FILE" || {
            echo "❌ Download failed. Please download manually."
            exit 1
        }
    else
        echo "❌ Neither wget nor curl found. Please install one."
        exit 1
    fi

    echo "Decompressing auth.txt.gz..."
    gunzip -k "$AUTH_FILE"
    echo "✅ auth.txt extracted to $AUTH_TXT"
fi

# Download redteam.txt.gz (ground truth labels)
REDTEAM_FILE="$DATA_DIR/redteam.txt.gz"
REDTEAM_TXT="$DATA_DIR/redteam.txt"

if [ -f "$REDTEAM_TXT" ]; then
    echo "✅ redteam.txt already exists. Skipping download."
else
    echo "Downloading redteam.txt.gz (ground truth labels)..."
    if command -v wget &>/dev/null; then
        wget -c "$BASE_URL/redteam.txt.gz" -O "$REDTEAM_FILE" 2>/dev/null || true
    elif command -v curl &>/dev/null; then
        curl -L -C - "$BASE_URL/redteam.txt.gz" -o "$REDTEAM_FILE" 2>/dev/null || true
    fi

    if [ -f "$REDTEAM_FILE" ]; then
        gunzip -k "$REDTEAM_FILE"
        echo "✅ redteam.txt extracted."
    else
        echo "⚠️  redteam.txt download failed (manual download may be required)."
    fi
fi

echo ""
echo "============================================"
echo "Dataset summary:"
if [ -f "$AUTH_TXT" ]; then
    LINE_COUNT=$(wc -l < "$AUTH_TXT" | tr -d ' ')
    FILE_SIZE=$(du -h "$AUTH_TXT" | cut -f1)
    echo "  auth.txt:    $LINE_COUNT lines ($FILE_SIZE)"
fi
if [ -f "$REDTEAM_TXT" ]; then
    RT_COUNT=$(wc -l < "$REDTEAM_TXT" | tr -d ' ')
    echo "  redteam.txt: $RT_COUNT labeled events"
fi
echo "============================================"
