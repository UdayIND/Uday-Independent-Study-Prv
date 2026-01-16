#!/bin/bash
# Validate that Zeek and Suricata generated telemetry logs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ZEEK_DIR="$REPO_ROOT/data/derived/zeek"
SURICATA_DIR="$REPO_ROOT/data/derived/suricata"

ERRORS=0

echo "Validating telemetry generation..."
echo ""

# Check Zeek logs
echo "Checking Zeek logs..."
if [ -f "$ZEEK_DIR/conn.log" ]; then
    CONN_SIZE=$(stat -f%z "$ZEEK_DIR/conn.log" 2>/dev/null || stat -c%s "$ZEEK_DIR/conn.log" 2>/dev/null || echo "0")
    if [ "$CONN_SIZE" -gt 0 ]; then
        CONN_LINES=$(wc -l < "$ZEEK_DIR/conn.log" 2>/dev/null || echo "0")
        echo "✓ conn.log exists ($CONN_SIZE bytes, $CONN_LINES lines)"
    else
        echo "✗ conn.log exists but is empty"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "✗ conn.log does not exist"
    ERRORS=$((ERRORS + 1))
fi

if [ -f "$ZEEK_DIR/dns.log" ]; then
    DNS_SIZE=$(stat -f%z "$ZEEK_DIR/dns.log" 2>/dev/null || stat -c%s "$ZEEK_DIR/dns.log" 2>/dev/null || echo "0")
    if [ "$DNS_SIZE" -gt 0 ]; then
        DNS_LINES=$(wc -l < "$ZEEK_DIR/dns.log" 2>/dev/null || echo "0")
        echo "✓ dns.log exists ($DNS_SIZE bytes, $DNS_LINES lines)"
    else
        echo "⚠️  dns.log exists but is empty (may be normal if no DNS traffic)"
    fi
else
    echo "⚠️  dns.log does not exist (may be normal if no DNS traffic)"
fi

echo ""

# Check Suricata logs
echo "Checking Suricata logs..."
if [ -f "$SURICATA_DIR/eve.json" ]; then
    EVE_SIZE=$(stat -f%z "$SURICATA_DIR/eve.json" 2>/dev/null || stat -c%s "$SURICATA_DIR/eve.json" 2>/dev/null || echo "0")
    if [ "$EVE_SIZE" -gt 0 ]; then
        EVE_LINES=$(wc -l < "$SURICATA_DIR/eve.json" 2>/dev/null || echo "0")
        echo "✓ eve.json exists ($EVE_SIZE bytes, $EVE_LINES lines)"
    else
        echo "✗ eve.json exists but is empty"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "✗ eve.json does not exist"
    ERRORS=$((ERRORS + 1))
fi

echo ""

# If errors, show Docker logs
if [ $ERRORS -gt 0 ]; then
    echo "=========================================="
    echo "Telemetry validation failed. Showing Docker logs:"
    echo "=========================================="
    echo ""
    echo "--- Zeek logs (last 50 lines) ---"
    docker compose logs --tail=50 zeek 2>/dev/null || echo "Could not retrieve Zeek logs"
    echo ""
    echo "--- Suricata logs (last 50 lines) ---"
    docker compose logs --tail=50 suricata 2>/dev/null || echo "Could not retrieve Suricata logs"
    echo ""
    echo "--- Directory contents ---"
    echo "Zeek directory ($ZEEK_DIR):"
    ls -lah "$ZEEK_DIR" 2>/dev/null || echo "Directory not found"
    echo ""
    echo "Suricata directory ($SURICATA_DIR):"
    ls -lah "$SURICATA_DIR" 2>/dev/null || echo "Directory not found"
    echo ""
    exit 1
fi

echo "✅ Telemetry validation passed!"
exit 0
