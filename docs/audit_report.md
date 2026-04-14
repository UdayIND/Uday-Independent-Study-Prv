# System Architecture Audit & Execution Readiness Assessment
**Target System**: SENTINEL-RL / GG-NS-RL (Graph-Grounded Neuro-Symbolic RL System)
**Environment**: Indiana University Quartz HPC Cluster (Slurm: `r01885`)
**User**: `udvall`

---

## 1. Executive Summary

This architecture audit evaluates the repository transition from its current state—a deterministic, rule-based offline Threat Detection Pipeline (SOC-Informed Discovery)—to the target **SENTINEL-RL / GG-NS-RL architecture**.

### 🚨 Current System Maturity: Bare-Metal Prototyping
The existing codebase provides a **solid heuristic baseline** but currently contains **0% Machine Learning, 0% Reinforcement Learning, 0% Graph Neural Networks, and 0% Large Language Models.** The system explicitly notes that "no machine learning or LLM inference is used," relying instead on mathematical heuristics (e.g., 5-factor confidence model) and string-template "Report Agents."

### ✅ Key Strengths (Foundation for RL)
1. **Strong Telemetry & Orchestration Stubs**: The ingestion layer (Zeek/Suricata to Parquet) and case assembly schemas are mature. You have a well-defined `13-field schema` for normalizations.
2. **Clear Agent Abstractions**: `TriageAgent`, `EvidenceAgent`, `CriticAgent`, and `ReportAgent` exist as cleanly decoupled modules, making them exceptional candidates to be replaced by actual LLM/RL policies.
3. **Evaluation Framework**: A robust ablation suite (`make ablation`) and diagnostic plotting already exist, creating an excellent baseline to prove that RL/GNN outperforms heuristic processing.

### 🛑 Critical Blockers (The Reality Check)
1. **Static Data Limitation**: The pipeline relies entirely on static, pre-generated PCAPs (`synthetic_scan.pcap` via Scapy). RL algorithms require interactive MDP environments; you cannot train PPO without an interactive simulation suite (e.g., CybORG) capable of dynamic state transitions conditioned on agent actions.
2. **Missing Representation Layer**: You cannot train GNNs without a graph database (Neo4j). Currently, events are flat tabular arrays in pandas/Parquet.
3. **No RL Infrastructure**: Zero PyTorch, Ray RLlib, or Stable-Baselines3 dependencies exist in `pyproject.toml`.

---

## 2. Phase Completion Status (RAG Framework)

| Phase | Goal | Status | % Done | Key Notes |
|-------|------|:---:|:---:|-----------|
| **Phase 1** | Symbolic + LLM Foundation | 🔴 **Amber/Red** | 15% | Log parsing exists (`src/ingest`). Triage pipeline exists but is purely rule-based. **Missing**: Neo4j graph schemas, actual LLM integration (vLLM/OpenAI API). |
| **Phase 2** | Simulation Twin | 🔴 **Red** | 5% | `scripts/generate_synthetic_pcaps.py` exists but is highly static. **Missing**: CybORG wrapper, OpenAI Gym/Gymnasium API compliance, dynamic red team interactive generation. |
| **Phase 3** | Monte Carlo / Offline RL | 🔴 **Red** | 0% | No PyTorch Geometric/DGL backend. No state space formulation. No trajectory memory buffers. |
| **Phase 4** | PPO-Based Response | 🔴 **Red** | 0% | Missing CleanRL/Ray library dependencies. Missing reward engineering, CMDP definitions, and continuous/discrete action spaces. |
| **Phase 5** | Shadow Mode Deployment | 🟡 **Amber** | 10% | Evidence bundles, traces (`agent_trace.jsonl`), and markdown reports exist as UI-stubs, meaning the "Read-Only Advisory" output structure is partially ready. |

---

## 3. System Architecture Assessment: Actual vs. Intended

### 3.1 Intended Architecture (SENTINEL-RL)
- **State Representation**: Neo4j streams AD + SIEM logs into PyTorch Geometric (PyG).
- **Decision Engine**: PPO agent routes investigations and deploys containment actions (CMDP).
- **Reasoning Layer**: LLM Critic validates states (Neuro-Symbolic) to prevent hallucinated actions.

### 3.2 Actual Architecture (`Uday-Independent-Study-Prv`)
- **State Representation**: Flat `events.parquet` dataframes operated on by `pandas.groupby`.
- **Decision Engine**: Hardcoded nested loops in `AgentOrchestrator.run()` with configurable `max_retries`.
- **Reasoning Layer**: `CriticAgent.py` calculates a weighted mathematical average of 5 static factors.

### 3.3 Integration & Scalability Gaps
- The current orchestrator is **synchronous and batch-oriented** (loads a whole PCAP into memory via Pandas). Training an RL agent requires millions of simulated steps; Pandas operations in the inner loop will absolutely destroy throughput and bottleneck your HPC allocation.

---

## 4. Critical Technical Gaps (Ranked)

### Gap 1: Absence of an Interactive RL Environment (Highest Impact, High Difficulty)
RL demands \\( S_t \rightarrow A_t \rightarrow R_t \rightarrow S_{t+1} \\). Existing scripts use static network PCAPs.
- **Action**: You must integrate CyberGym or CybORG. You need a wrapper that takes an action (e.g., "query process list on IP X," "block Port Y") and synthetically advances the network state to return a new observation vector and sparse reward.

### Gap 2: Flat State vs. Graph State (High Impact, Medium Difficulty)
The system currently normalizes into tabular DataFrames. GNN encodings require Nodes (Alerts, IPs, Users) and Edges (Connections, Parent-Child Processes).
- **Action**: Build a Neo4j ingestion pipeline. Implement a PyTorch Geometric `Data` extraction script that turns your 13-field Zeek/Suricata Parquet files into a Heterogeneous Graph (`HeteroData`).

### Gap 3: Defining the Reward Engineering System (Research Significance: PhD Level)
Rule-based systems don't have rewards; RL systems live or die by them.
- **Action**: Define sparse/delayed rewards.
  - *Positive*: +1.0 for identifying the true patient zero / attack path.
  - *Negative*: -0.01 penalty per investigation step (efficiency), -1.0 for false containment (CMDP boundary violation).

### Gap 4: LLM Critic Overhead (Scalability)
Querying an LLM as a Critic or Triage validator dynamically inside an RL rollout loop will grind training to a halt due to inference latency (even on an HPC).
- **Action**: The LLM needs to act asynchronously or be distilled. Generate trajectories offline with the LLM Critic labeling them, then train the PPO agent purely on the numerical state embeddings via Offline RL.

---

## 5. Quartz HPC Execution Roadmap (2–3 Weeks)

Indiana University Quartz cluster (`r01885`) is standard Slurm compute architecture. We must heavily leverage `sbatch` job arrays to overcome the simulation bottleneck.

### Week 1: Environment & CybORG Simulation Pipeline
**Goal**: Build the RL environment and multi-node rollout capability.
* **Task 1.1**: Wrap CybORG in a `gymnasium` interface, mapping your custom 13-field network states into observations.
* **Task 1.2**: Write Slurm job arrays to run 1,000 independent CybORG simulations acting as an offline dataset generation pipeline.
```bash
#!/bin/bash
#SBATCH --job-name=generate_offline_traj
#SBATCH --account=r01885
#SBATCH --partition=compute
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=16
#SBATCH --time=12:00:00
#SBATCH --array=1-50  # 50 parallel instances

module load python/3.11
source venv/bin/activate
python scripts/run_cyborg_sim.py --seed ${SLURM_ARRAY_TASK_ID} --output data/trajectories/
```

### Week 2: Graph Database & GNN Encoder Execution
**Goal**: Convert trajectories into graph states and train the PyG encoder.
* **Task 2.1**: Spin up a headless Neo4j container in your Slurm job using Singularity/Docker.
* **Task 2.2**: Map the generated cybORG trajectories into the graph and export Heterogeneous Graph objects.
* **Task 2.3**: Train the GNN (GraphSAGE / GAT) on a GPU node to act as your RL observation feature extractor.
```bash
#!/bin/bash
#SBATCH --job-name=train_gnn_encoder
#SBATCH --account=r01885
#SBATCH --partition=gpu
#SBATCH --gpus=1
#SBATCH --time=24:00:00
python scripts/train_gnn.py --data_dir data/trajectories/graphs
```

### Week 3: PPO Distributed Training & LLM Critic
**Goal**: Train the SENTINEL-RL policy.
* **Task 3.1**: Integrate Ray RLlib or CleanRL to parallelize PPO training across multiple compute nodes.
* **Task 3.2**: Hook in the LLM Critic (vLLM hosted on a dedicated GPU node communicating via local port) to score candidate actions.
```bash
#!/bin/bash
#SBATCH --job-name=sentinel_ppo_ray
#SBATCH --account=r01885
#SBATCH --partition=gpu
#SBATCH --nodes=2
#SBATCH --gpus-per-node=2
#SBATCH --time=48:00:00
ray start --head
python scripts/train_ppo_ray.py --config configs/ppo_soc.yaml
```

---

## 6. Strategic Recommendations to Reach SOTA (2025/2026)

To ensure this research achieves rigorous PhD-level validation:

1. **Rip Out the Orchestrator For Training**: Move from standard `pandas` and nested `for` loops in `AgentOrchestrator` to **vectorized environments**. RL demands step throughput > 5,000 steps/sec. Operations traversing Parquet files per step will bottleneck GPUs.
2. **Offline RL (Decision Transformer / CQL) over Online PPO**: SOC environments are too dangerous for online exploration. State-of-the-art leans heavily towards Offline RL (like Conservative Q-Learning) trained on the massive offline datasets generated by CybORG, rather than Online PPO. Explore Offline RL inside RLlib.
3. **LLM Knowledge Distillation**: Calling an LLM Critic during RL rollouts is inherently unscalable. You should use the LLM to score/reward *offline* trajectory datasets, then train a lightweight Multi-Layer Perceptron (Reward Model) on those scores. The RL agent then trains against the fast RM, not the slow LLM.
4. **Implement CMDP via Lagrangian Relaxation**: Standard RL ignores constraints. You must implement a Constrained MDP where the agent maximizes threat disruption *(Reward)* whilst ensuring critical servers (e.g., internal DNS) are not isolated *(Cost)*. Use PPO-Lagrangian algorithms.
5. **Utilize Ray (RLlib)**: Don't write PPO from scratch. Ray handles distributed HPC scaling beautifully out-of-the-box and aligns perfectly with Slurm clusters.

*End of Audit.*
