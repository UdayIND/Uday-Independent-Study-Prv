#!/bin/bash
#SBATCH --job-name=sentinel-rl-train
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=128G
#SBATCH --time=12:00:00
#SBATCH --partition=general
#SBATCH --output=experiments/logs/train-%j.out
#SBATCH --error=experiments/logs/train-%j.err

# =============================================================================
# SENTINEL-RL: PPO Policy Training on IU Quartz
# Section VI-C: 200 iterations, 5 seeds
# =============================================================================

echo "=========================================="
echo "SENTINEL-RL PPO Training"
echo "Node: $(hostname)"
echo "Date: $(date)"
echo "=========================================="

# Load modules (IU Quartz)
module load python/3.11 2>/dev/null || true

# Activate environment
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Create output directories
mkdir -p experiments/logs experiments/checkpoints experiments/results

# Training parameters from Table I
NUM_ITERATIONS=${NUM_ITERATIONS:-200}
NUM_SEEDS=${NUM_SEEDS:-5}

echo "Training config:"
echo "  Iterations: $NUM_ITERATIONS"
echo "  Seeds: $NUM_SEEDS"
echo ""

# Run training (Ray will use all available CPUs)
python -m src.model.train \
    --num-iterations "$NUM_ITERATIONS" \
    --num-seeds "$NUM_SEEDS" \
    2>&1 | tee "experiments/logs/train-$(date +%Y%m%d_%H%M%S).log"

echo ""
echo "Training complete at $(date)"
