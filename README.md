# SENTINEL-RL

> **Offloading Topological Reasoning from LLM Agents in the Security Operations Center**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

SENTINEL-RL is a four-plane neuro-symbolic agentic SOC that offloads topological reasoning from an LLM onto a heterogeneous graph encoder and a PPO-trained reinforcement learning policy. The system was evaluated end-to-end on the [LANL Comprehensive, Multi-Source Cyber-Security Events Dataset](https://csr.lanl.gov/data/cyber1/).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SENTINEL-RL Architecture                     │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│  Data Plane  │Strategic Plane│Telemetry Plane│ Orchestration Plane│
├──────────────┼──────────────┼──────────────┼────────────────────┤
│ LANL auth.txt│ HetGAT       │ AlertEngine  │ Triage Agent (LLM) │
│ → Neo4j      │ Encoder      │ (W=10s,N=25) │ Critic Agent (LLM) │
│ Two-phase    │ (64-d state) │ → Webhook    │ HITL Gate          │
│ CREATE       │ PPO Policy   │              │ Streamlit UI       │
│ (Listing 1)  │ (5 actions)  │              │                    │
└──────────────┴──────────────┴──────────────┴────────────────────┘
```

### Key Results (Table III)

| Metric | Value |
|---|---|
| Ingestion throughput | 24M edges / 14.2 min (24× over MERGE) |
| Alert latency (p99) | ≤ 2.45 s |
| Mean episodic return | 8.74 ± 0.31 |
| Precision | 0.91 |
| Recall | 0.87 |
| E2E detect→contain | 6.3 s median |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Neo4j 5.x (via Docker or standalone)
- Optional: CUDA GPU (for HetGAT training)

### 1. Clone and install

```bash
git clone https://github.com/UdayIND/Uday-Independent-Study-Prv.git
cd Uday-Independent-Study-Prv
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your Neo4j credentials and (optionally) OPENAI_API_KEY
```

### 3. Download LANL dataset

```bash
bash scripts/download_lanl.sh
```

> **Note:** The LANL dataset requires accepting their [terms of use](https://csr.lanl.gov/data/cyber1/). The download script will guide you.

### 4. Start Neo4j

```bash
docker compose up -d neo4j
```

### 5. Ingest LANL data into Neo4j

```bash
python -m src.ingest.lanl_loader --auth-path data/lanl/auth.txt
```

### 6. Train the PPO policy

```bash
python -m src.model.train
```

### 7. Evaluate

```bash
python scripts/evaluate.py --checkpoint data/models/ppo_policy_checkpoint
```

---

## Single-Command Reproduction

```bash
bash reproduce.sh
```

This script runs the full pipeline: dataset download → ingestion → training → evaluation.

---

## Project Structure

```
sentinel-rl/
├── configs/
│   ├── sentinel_rl.yaml          # Master config (Table I hyperparameters)
│   └── detector.yaml             # Heuristic detector thresholds
├── hpc/
│   ├── slurm_train.sbatch        # PPO training (IU Quartz)
│   ├── slurm_ingest.sbatch       # Neo4j ingestion
│   └── slurm_anchor.sbatch       # Anchor-node co-location (Section V-B)
├── scripts/
│   ├── download_lanl.sh          # Dataset download
│   ├── ingest_lanl.py            # Ingestion benchmark (Table II)
│   └── evaluate.py               # Detection evaluation (Table III)
├── src/
│   ├── agents/
│   │   ├── triage_agent.py       # LLM narrative synthesis (Section IV-D)
│   │   ├── critic_agent.py       # Tiered action gating (Section VII-E)
│   │   ├── evidence_agent.py     # Evidence retrieval & scoring
│   │   ├── report_agent.py       # Case report generation
│   │   └── orchestrator.py       # Multi-agent orchestration loop
│   ├── ingest/
│   │   ├── lanl_loader.py        # LANL auth.txt → Neo4j (Listing 1)
│   │   ├── alert_engine.py       # Sliding-window alerting (Section IV-C)
│   │   └── live_ingestion.py     # Kafka streaming consumer
│   ├── model/
│   │   ├── encoder.py            # HetGAT encoder (Section IV-B)
│   │   ├── env.py                # Gymnasium MDP (5 actions, sparse reward)
│   │   ├── train.py              # Ray RLlib PPO training
│   │   └── inference.py          # PPO policy serving
│   ├── eval/                     # Evaluation metrics & plots
│   ├── detect_baseline/          # Heuristic detectors (recon, DNS beaconing)
│   ├── normalize/                # Event schema normalization
│   ├── report/                   # Run manifest generation
│   ├── ui/app.py                 # Streamlit analyst workbench
│   ├── api.py                    # FastAPI policy endpoint
│   ├── config.py                 # Environment configuration
│   └── main.py                   # Batch pipeline entry point
├── tests/                        # Pytest suite
├── hpc/                          # SLURM job scripts
├── .env.example                  # Configuration template
├── docker-compose.yml            # Neo4j + services
├── Dockerfile
├── Makefile
├── pyproject.toml
├── reproduce.sh                  # Single-command reproducer
└── CITATION.cff
```

---

## HPC Deployment (IU Quartz)

The system uses the **anchor-node co-location pattern** (Section V-B): all services run on a single 32-core, 128 GB node to avoid cross-node latency.

```bash
# Training
sbatch hpc/slurm_train.sbatch

# Full system (Neo4j + FastAPI + Streamlit + Ingestion)
sbatch hpc/slurm_anchor.sbatch
```

---

## API Endpoints

Start the FastAPI server:

```bash
uvicorn src.api:app --host 0.0.0.0 --port 8000
```

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | System health check |
| `/predict` | POST | Batch threat prediction |
| `/train` | POST | Trigger model retraining |

Interactive docs: `http://localhost:8000/docs`

---

## Configuration

All hyperparameters from Table I are centralized in `configs/sentinel_rl.yaml`:

| Parameter | Value | Paper Reference |
|---|---|---|
| `train_batch_size_per_learner` | 4000 | Table I |
| `minibatch_size` | 128 | Table I |
| `num_epochs` | 10 | Table I |
| `lr` | 5e-5 | Table I |
| `clip_param` | 0.2 | Table I |
| `entropy_coeff` | 0.01 | Table I |
| `gamma` | 0.99 | Table I |
| `lambda_` | 0.95 | Table I |
| `alert_window` | 10 s | Section IV-C |
| `alert_threshold` | 25 events | Section IV-C |

---

## Testing

```bash
pytest tests/ -v
```

---

## Citation

```bibtex
@misc{sentinel_rl_2026,
  title={SENTINEL-RL: Offloading Topological Reasoning from LLM Agents in the Security Operations Center},
  author={Hiwase, Uday},
  year={2026},
  institution={Indiana University}
}
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [LANL Cyber Security Dataset](https://csr.lanl.gov/data/cyber1/) (Kent, 2015)
- [Ray/RLlib](https://docs.ray.io/en/latest/rllib/) (Liang et al., 2018)
- [PyTorch Geometric](https://pyg.org/) (Fey & Lenssen, 2019)
- [Neo4j](https://neo4j.com/) Graph Database
- Indiana University Research Computing (Quartz HPC)
