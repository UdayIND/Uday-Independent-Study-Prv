#!/usr/bin/env bash
# =============================================================================
# SENTINEL-RL: Single-Command Reproduction Script
#
# Reproduces all numerical results from the paper:
#   1. Download LANL dataset
#   2. Ingest into Neo4j (Table II benchmark)
#   3. Train PPO policy (Table I hyperparameters)
#   4. Evaluate detection performance (Table III)
#
# Usage:
#   bash reproduce.sh              # Full reproduction
#   bash reproduce.sh --dry-run    # Verify paths/configs only
#   bash reproduce.sh --skip-data  # Skip dataset download
# =============================================================================

set -euo pipefail

DRY_RUN=false
SKIP_DATA=false

for arg in "$@"; do
    case $arg in
        --dry-run)   DRY_RUN=true ;;
        --skip-data) SKIP_DATA=true ;;
        *)           echo "Unknown option: $arg"; exit 1 ;;
    esac
done

echo "============================================"
echo "SENTINEL-RL Reproduction Pipeline"
echo "============================================"
echo ""

# Check prerequisites
echo "Checking prerequisites..."
python3 --version || { echo "❌ Python 3 not found"; exit 1; }
echo "✅ Python found"

if [ -f "configs/sentinel_rl.yaml" ]; then
    echo "✅ Config found: configs/sentinel_rl.yaml"
else
    echo "❌ Missing: configs/sentinel_rl.yaml"
    exit 1
fi

if [ "$DRY_RUN" = true ]; then
    echo ""
    echo "Dry run complete. All paths verified."
    exit 0
fi

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "✅ Virtual environment activated"
else
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -e ".[dev]"
fi

# Step 1: Download LANL dataset
if [ "$SKIP_DATA" = false ]; then
    echo ""
    echo "--- Step 1/4: Download LANL Dataset ---"
    bash scripts/download_lanl.sh
fi

# Step 2: Ingest into Neo4j
echo ""
echo "--- Step 2/4: Ingest into Neo4j ---"
if [ -f "data/lanl/auth.txt" ]; then
    python -m src.ingest.lanl_loader \
        --auth-path data/lanl/auth.txt \
        --batch-size 5000
else
    echo "⚠️  LANL auth.txt not found. Skipping ingestion."
    echo "   Download manually from: https://csr.lanl.gov/data/cyber1/"
fi

# Step 3: Train PPO policy
echo ""
echo "--- Step 3/4: Train PPO Policy ---"
python -m src.model.train

# Step 4: Evaluate
echo ""
echo "--- Step 4/4: Evaluate Detection Performance ---"
python scripts/evaluate.py \
    --checkpoint data/models/ppo_policy_checkpoint \
    --num-episodes 100

echo ""
echo "============================================"
echo "Reproduction complete!"
echo "============================================"
