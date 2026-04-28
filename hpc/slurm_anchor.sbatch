#!/bin/bash
#SBATCH --job-name=sentinel-rl-anchor
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=128G
#SBATCH --time=24:00:00
#SBATCH --partition=general
#SBATCH --output=experiments/logs/anchor-%j.out
#SBATCH --error=experiments/logs/anchor-%j.err

# =============================================================================
# SENTINEL-RL: Anchor-Node Co-location Pattern (Section V-B)
#
# All interactive microservices (Neo4j, FastAPI Policy Endpoint, Streamlit
# Analyst Workbench, AlertEngine) are co-located on a single 32-core
# anchor node to eliminate cross-node latency jitter.
# =============================================================================

echo "=========================================="
echo "SENTINEL-RL Anchor Node"
echo "Node: $(hostname)"
echo "Date: $(date)"
echo "CPUs: $(nproc)"
echo "Memory: $(free -h | grep Mem | awk '{print $2}')"
echo "=========================================="

module load python/3.11 2>/dev/null || true

if [ -d "venv" ]; then
    source venv/bin/activate
fi

mkdir -p experiments/logs

# --- Service 1: Neo4j (via Docker/Singularity if available) ---
echo "[1/4] Starting Neo4j..."
if command -v docker &>/dev/null; then
    docker compose up -d neo4j 2>/dev/null || echo "Neo4j Docker start failed — using external instance"
else
    echo "Docker not available — assuming external Neo4j at \$NEO4J_URI"
fi
sleep 10

# --- Service 2: FastAPI Policy Endpoint ---
echo "[2/4] Starting FastAPI Policy Endpoint (port 8000)..."
uvicorn src.api:app --host 127.0.0.1 --port 8000 &
POLICY_PID=$!
sleep 3

# --- Service 3: Live Ingestion Engine ---
echo "[3/4] Starting Telemetry Ingestion Engine..."
python -m src.ingest.live_ingestion &
INGEST_PID=$!

# --- Service 4: Streamlit Analyst Workbench ---
echo "[4/4] Starting Analyst Workbench (port 8501)..."
streamlit run src/ui/app.py --server.port 8501 --server.address 127.0.0.1 &
UI_PID=$!

echo ""
echo "=========================================="
echo "All services running:"
echo "  FastAPI:   http://$(hostname):8000/docs"
echo "  Streamlit: http://$(hostname):8501"
echo "  PIDs: Policy=$POLICY_PID Ingest=$INGEST_PID UI=$UI_PID"
echo "=========================================="

# Wait for all background processes
wait $POLICY_PID $INGEST_PID $UI_PID
