#!/bin/bash
#SBATCH --job-name=sentinel-rl-ingest
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=64G
#SBATCH --time=02:00:00
#SBATCH --partition=general
#SBATCH --output=experiments/logs/ingest-%j.out
#SBATCH --error=experiments/logs/ingest-%j.err

# =============================================================================
# SENTINEL-RL: LANL Ingestion into Neo4j
# Section V-A: Two-phase CREATE pattern benchmark
# =============================================================================

echo "=========================================="
echo "SENTINEL-RL LANL Ingestion"
echo "Node: $(hostname)"
echo "Date: $(date)"
echo "=========================================="

module load python/3.11 2>/dev/null || true

if [ -d "venv" ]; then
    source venv/bin/activate
fi

mkdir -p experiments/logs

AUTH_PATH=${AUTH_PATH:-data/lanl/auth.txt}
NEO4J_URI=${NEO4J_URI:-neo4j://localhost:7687}
NEO4J_USER=${NEO4J_USER:-neo4j}
NEO4J_PASSWORD=${NEO4J_PASSWORD:-password}

echo "Ingesting LANL auth.txt into Neo4j..."
echo "  Auth path: $AUTH_PATH"
echo "  Neo4j: $NEO4J_URI"
echo ""

python -m src.ingest.lanl_loader \
    --auth-path "$AUTH_PATH" \
    --neo4j-uri "$NEO4J_URI" \
    --neo4j-user "$NEO4J_USER" \
    --neo4j-password "$NEO4J_PASSWORD" \
    --batch-size 5000 \
    2>&1 | tee "experiments/logs/ingest-$(date +%Y%m%d_%H%M%S).log"

echo ""
echo "Ingestion complete at $(date)"
