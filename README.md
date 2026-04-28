# SENTINEL-RL: SOC-Informed Discovery

## 1. Project Title & Overview
**SOC-Informed Discovery** is an end-to-end cybersecurity threat detection pipeline and backend. It leverages heuristic baselines and unsupervised Machine Learning (Isolation Forest) to analyze network telemetry (Zeek/Suricata), identify anomalies, and assemble security cases for Agentic SOC triage.

### Key Features
- **Data Ingestion:** Parses and normalizes raw Zeek and Suricata logs into unified structures.
- **Machine Learning Pipeline:** Extracts behavioral features (e.g., unique ports/hosts scanned per IP) and trains an anomaly detection model.
- **Real-Time API Backend:** Provides a FastAPI service for live threat prediction and background retraining.
- **Analyst Workbench UI:** Optional Streamlit frontend to interact with the graph database and RL policy agent.

### High-Level Architecture
1. **Telemetry Parsers**: `src/ingest/` reads raw logs.
2. **Normalizer**: `src/normalize/` outputs clean Parquet files.
3. **ML Model**: `src/model/` trains an Isolation Forest on aggregated telemetry features to detect anomalies.
4. **FastAPI Backend**: `src/api.py` exposes REST endpoints for live prediction.

---

## 2. Setup Instructions

### Prerequisites
- Python 3.9+
- Pip and virtual environment support (`venv` or `conda`)

### Installation Steps
1. **Clone the repository:**
   ```bash
   git clone https://github.com/UdayIND/Uday-Independent-Study-Prv.git
   cd Uday-Independent-Study-Prv
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -e .
   ```

### Environment Setup
Copy the configuration template and edit if necessary:
```bash
cp .env.example .env
```
The application uses these values via `src/config.py` to connect to Kafka, Neo4j, and the FastAPI host.

---

## 3. How to Run

### Training the Model
To train the Anomaly Detection model on existing normalized data in `data/normalized`:
```bash
python -m src.model.train
```
*Outputs: Artifacts will be saved to `data/models/isolation_forest_v_latest.joblib`.*

### Running the Backend/API
Start the FastAPI server:
```bash
uvicorn src.api:app --host 0.0.0.0 --port 8000 --reload
```

### Running Inference (Batch Pipeline)
You can run the full end-to-end heuristic + ML pipeline on a PCAP file:
```bash
python -m src.main --pcap data/sample.pcap --config configs/detector.yaml
```

---

## 4. Example Usage

**1. Predict Anomalies from Python:**
```python
from src.model.inference import ThreatPredictor

predictor = ThreatPredictor()
events = [{"src_ip": "10.0.0.1", "event_type": "CONNECT", "dst_port": 22, "dst_ip": "192.168.1.5"}]
results = predictor.predict(events)
print(results)
```

**2. Example Output:**
```json
[
  {
    "src_ip": "10.0.0.1",
    "is_threat": true,
    "risk_score": 0.0543,
    "metrics": {
      "total_events": 1.0,
      "unique_dst_ports": 1.0,
      "unique_dst_ips": 1.0
    }
  }
]
```

---

## 5. API Usage

When the server is running at `http://127.0.0.1:8000`, the following endpoints are available. Interactive Swagger docs can be accessed at `http://127.0.0.1:8000/docs`.

### GET `/health`
Check API status and model readiness.
- **Response:** `{"status": "ok", "model_loaded": true}`

### POST `/predict`
Run anomaly detection on a batch of telemetry events.
- **Payload:**
  ```json
  {
    "events": [
      {
        "src_ip": "192.168.1.100",
        "event_type": "CONNECT",
        "dst_port": 80,
        "dst_ip": "8.8.8.8"
      }
    ]
  }
  ```
- **Response:**
  ```json
  {
    "status": "success",
    "predictions": [
      {
        "src_ip": "192.168.1.100",
        "is_threat": false,
        "risk_score": -0.1502,
        "metrics": {"total_events": 1.0, "unique_dst_ports": 1.0, "unique_dst_ips": 1.0}
      }
    ]
  }
  ```

### POST `/train`
Asynchronously triggers model retraining on the backend.
- **Response:** `{"status": "processing", "message": "Model training started in background."}`

---

## 6. Project Structure

```text
├── .env.example           # Configuration template
├── Makefile               # Shortcuts for setup/testing
├── pyproject.toml         # Python dependencies
├── README.md              # Project documentation
├── configs/               # Detector YAML config rules
├── data/                  # Telemetry, PCAPs, Models
│   ├── normalized/        # Parquet data ready for training
│   └── models/            # Saved `.joblib` model artifacts
├── scripts/               # Utility scripts
├── src/                   # Core Codebase
│   ├── api.py             # FastAPI backend
│   ├── config.py          # Environment settings loader
│   ├── main.py            # End-to-end batch pipeline
│   ├── ingest/            # Zeek/Suricata log parsers & streaming consumers
│   ├── normalize/         # Event schema normalizers
│   ├── model/             # Machine Learning logic
│   │   ├── train.py       # Isolation Forest training script
│   │   └── inference.py   # Prediction wrapper
│   └── ui/                # Streamlit Analyst Workbench
└── tests/                 # Pytest suite
```

---

## 7. Notes & Assumptions
- **Dependency on Parsed Data:** The ML model (`train.py`) assumes that raw `.pcap` files have already been parsed into Zeek/Suricata logs and stored as `.parquet` files in `data/normalized/`. If the directory is empty, run `src/main.py` first.
- **Mock External Systems:** Features connecting to Neo4j or Kafka (`live_ingestion.py`) will gracefully fallback or drop events if the infrastructure (Docker containers) is unavailable.
- **Frontend Status:** The `src/ui/app.py` Streamlit frontend is included for demonstration purposes but is currently optional.
