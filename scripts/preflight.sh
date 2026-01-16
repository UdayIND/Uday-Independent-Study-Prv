#!/bin/bash
# Preflight checks for SOC-Informed Discovery pipeline
# Verifies environment and prerequisites before running the pipeline

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ERRORS=0
WARNINGS=0

echo "=========================================="
echo "SOC-Informed Discovery Preflight Checks"
echo "=========================================="
echo ""

# Check Python version
echo "1. Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 9 ]; then
        echo "   ✓ Python $PYTHON_VERSION (meets requirement: 3.9+)"
    else
        echo "   ✗ Python $PYTHON_VERSION (requires 3.9+)"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "   ✗ Python 3 not found"
    ERRORS=$((ERRORS + 1))
fi

# Check Docker
echo ""
echo "2. Checking Docker..."
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version 2>&1)
    echo "   ✓ Docker installed: $DOCKER_VERSION"

    # Check if Docker daemon is running
    if docker info > /dev/null 2>&1; then
        echo "   ✓ Docker daemon is running"
    else
        echo "   ⚠ Docker daemon is not running (pipeline will skip Zeek/Suricata)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "   ⚠ Docker not found (pipeline will skip Zeek/Suricata processing)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check Docker Compose
echo ""
echo "3. Checking Docker Compose..."
if docker compose version > /dev/null 2>&1; then
    COMPOSE_VERSION=$(docker compose version 2>&1 | head -1)
    echo "   ✓ Docker Compose available: $COMPOSE_VERSION"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_VERSION=$(docker-compose --version 2>&1)
    echo "   ⚠ Legacy docker-compose found: $COMPOSE_VERSION"
    echo "   ⚠ Consider upgrading to 'docker compose' (v2.x)"
    WARNINGS=$((WARNINGS + 1))
else
    echo "   ⚠ Docker Compose not found (pipeline will skip Zeek/Suricata)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check Make
echo ""
echo "4. Checking Make..."
if command -v make &> /dev/null; then
    MAKE_VERSION=$(make --version 2>&1 | head -1)
    echo "   ✓ Make available: $MAKE_VERSION"
else
    echo "   ✗ Make not found"
    ERRORS=$((ERRORS + 1))
fi

# Check required directories
echo ""
echo "5. Checking directory structure..."
REQUIRED_DIRS=(
    "src"
    "tests"
    "configs"
    "scripts"
    "data/raw"
    "data/derived/zeek"
    "data/derived/suricata"
    "data/normalized"
    "reports/runs"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$REPO_ROOT/$dir" ]; then
        echo "   ✓ $dir/"
    else
        echo "   ✗ Missing: $dir/"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check virtual environment
echo ""
echo "6. Checking virtual environment..."
if [ -d "$REPO_ROOT/venv" ]; then
    echo "   ✓ Virtual environment exists (venv/)"
    if [ -f "$REPO_ROOT/venv/bin/activate" ]; then
        echo "   ✓ Virtual environment appears valid"
    else
        echo "   ⚠ Virtual environment may be incomplete (run 'make setup')"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "   ⚠ Virtual environment not found (run 'make setup')"
    WARNINGS=$((WARNINGS + 1))
fi

# Check configuration files
echo ""
echo "7. Checking configuration files..."
REQUIRED_CONFIGS=(
    "configs/detector.yaml"
    "configs/zeek/local.zeek"
    "configs/suricata/suricata.yaml"
)

for config in "${REQUIRED_CONFIGS[@]}"; do
    if [ -f "$REPO_ROOT/$config" ]; then
        echo "   ✓ $config"
    else
        echo "   ✗ Missing: $config"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check .gitignore
echo ""
echo "8. Checking .gitignore..."
if [ -f "$REPO_ROOT/.gitignore" ]; then
    if grep -q "data/raw/\*.pcap" "$REPO_ROOT/.gitignore"; then
        echo "   ✓ PCAP files are gitignored"
    else
        echo "   ⚠ PCAP files may not be gitignored"
        WARNINGS=$((WARNINGS + 1))
    fi

    if grep -q "reports/runs/" "$REPO_ROOT/.gitignore"; then
        echo "   ✓ Report outputs are gitignored"
    else
        echo "   ⚠ Report outputs may not be gitignored"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "   ⚠ .gitignore not found"
    WARNINGS=$((WARNINGS + 1))
fi

# Summary
echo ""
echo "=========================================="
echo "Preflight Summary"
echo "=========================================="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo "✅ All checks passed! Ready to run pipeline."
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo "⚠️  Preflight completed with warnings. Pipeline may run with limited functionality."
    echo ""
    echo "Recommendations:"
    if [ $WARNINGS -gt 0 ]; then
        echo "- Start Docker Desktop if you want Zeek/Suricata processing"
        echo "- Run 'make setup' if virtual environment is missing"
    fi
    exit 0
else
    echo "❌ Preflight failed with $ERRORS error(s). Please fix issues before running pipeline."
    exit 1
fi
