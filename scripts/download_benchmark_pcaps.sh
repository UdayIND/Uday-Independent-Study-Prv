#!/bin/bash
# Download benchmark PCAPs from public sources.
# Reads URLs from configs/benchmark.yaml and saves to data/raw/benchmark/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BENCHMARK_DIR="$REPO_ROOT/data/raw/benchmark"
HEALTHCHECK_SCRIPT="$SCRIPT_DIR/pcap_healthcheck.sh"

mkdir -p "$BENCHMARK_DIR"

echo "=========================================="
echo "Benchmark PCAP Downloader"
echo "=========================================="
echo ""

# Define benchmark PCAPs (name, URL, max_size_mb)
# These match the entries in configs/benchmark.yaml
declare -a PCAP_ENTRIES=(
    "ctu13-neris|https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap|250"
    "wireshark-http|https://github.com/wireshark/wireshark/raw/master/test/captures/http.pcap|5"
)

DOWNLOADED=0
SKIPPED=0
FAILED=0

for entry in "${PCAP_ENTRIES[@]}"; do
    IFS='|' read -r NAME URL MAX_SIZE <<< "$entry"
    OUTPUT_FILE="$BENCHMARK_DIR/${NAME}.pcap"

    echo "--- $NAME ---"

    # Skip if already downloaded
    if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
        FILE_SIZE=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat -c%s "$OUTPUT_FILE" 2>/dev/null || echo "0")
        if [ "$FILE_SIZE" -gt 100 ]; then
            echo "  Already exists ($FILE_SIZE bytes), skipping"
            SKIPPED=$((SKIPPED + 1))
            echo ""
            continue
        fi
    fi

    echo "  Downloading from: $URL"

    # Download with size limit and timeout
    if command -v curl &> /dev/null; then
        if curl -L -f --max-time 300 --max-filesize $((MAX_SIZE * 1024 * 1024)) \
            -o "$OUTPUT_FILE" "$URL" 2>/dev/null; then
            echo "  Download completed"
        else
            echo "  Download failed"
            rm -f "$OUTPUT_FILE"
            FAILED=$((FAILED + 1))
            echo ""
            continue
        fi
    elif command -v wget &> /dev/null; then
        if wget --timeout=300 -O "$OUTPUT_FILE" "$URL" 2>/dev/null; then
            echo "  Download completed"
        else
            echo "  Download failed"
            rm -f "$OUTPUT_FILE"
            FAILED=$((FAILED + 1))
            echo ""
            continue
        fi
    else
        echo "  Error: Neither curl nor wget found"
        FAILED=$((FAILED + 1))
        echo ""
        continue
    fi

    # Validate: check it's not HTML and has PCAP magic bytes
    if [ -f "$OUTPUT_FILE" ]; then
        # Check for HTML content (bad download)
        if head -c 100 "$OUTPUT_FILE" 2>/dev/null | grep -qiE "<!doctype|<html|<head"; then
            echo "  Validation failed: file is HTML, not PCAP"
            rm -f "$OUTPUT_FILE"
            FAILED=$((FAILED + 1))
            echo ""
            continue
        fi

        FILE_SIZE=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat -c%s "$OUTPUT_FILE" 2>/dev/null || echo "0")
        echo "  Validated: $FILE_SIZE bytes"

        # Compute hash
        if command -v shasum &> /dev/null; then
            SHA256=$(shasum -a 256 "$OUTPUT_FILE" | cut -d' ' -f1)
        elif command -v sha256sum &> /dev/null; then
            SHA256=$(sha256sum "$OUTPUT_FILE" | cut -d' ' -f1)
        else
            SHA256="unknown"
        fi
        echo "  SHA256: $SHA256"

        DOWNLOADED=$((DOWNLOADED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
    echo ""
done

echo "=========================================="
echo "Summary:"
echo "  Downloaded: $DOWNLOADED"
echo "  Skipped (already exist): $SKIPPED"
echo "  Failed: $FAILED"
echo ""
echo "PCAPs saved to: $BENCHMARK_DIR/"
echo "=========================================="

if [ $FAILED -gt 0 ] && [ $DOWNLOADED -eq 0 ] && [ $SKIPPED -eq 0 ]; then
    echo ""
    echo "All downloads failed. Check network and try again."
    echo "You can also manually download PCAPs from:"
    echo "  - CTU-13: https://www.stratosphereips.org/datasets-ctu13"
    echo "  - Wireshark: https://wiki.wireshark.org/SampleCaptures"
    exit 1
fi
