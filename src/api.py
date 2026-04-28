"""
SENTINEL-RL API Backend.

Serves PPO policy inference, batch prediction, and training endpoints
via FastAPI. Referenced by the Streamlit Analyst Workbench (src/ui/app.py)
and the AlertEngine webhook (src/ingest/alert_engine.py).
"""

import logging
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel

from src.model.inference import ThreatPredictor
from src.model.train import train_model

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SENTINEL-RL SOC API",
    description="Real-time inference backend for the SENTINEL-RL Agentic SOC.",
    version="1.0.0",
)

# Initialize Predictor lazily on startup
predictor: ThreatPredictor | None = None


@app.on_event("startup")
def load_model():
    global predictor
    logger.info("Initializing ThreatPredictor...")
    predictor = ThreatPredictor()
    if not predictor.ready:
        logger.warning(
            "Predictor failed to load model. "
            "/predict endpoint will fail until /train is triggered."
        )


# --- Request/Response Models ---


class EventPayload(BaseModel):
    events: list[dict[str, Any]]


class ActionRequest(BaseModel):
    """Request for single-state policy action (used by Streamlit UI)."""

    alert_id: str = ""
    state_vector: list[float] = []


class InvestigationTrigger(BaseModel):
    """Webhook payload from AlertEngine."""

    node_id: str
    event_count: int
    time_window: int
    timestamp: str = ""


# --- Endpoints ---


@app.get("/health")
def health_check():
    """System health check endpoint."""
    return {"status": "ok", "model_loaded": predictor.ready if predictor else False}


@app.post("/predict")
def predict_threats(payload: EventPayload):
    """Batch threat prediction for a list of events.

    Returns action recommendations for each event.
    """
    if not predictor or not predictor.ready:
        raise HTTPException(status_code=503, detail="Model not loaded. Trigger training first.")

    try:
        results = predictor.predict(payload.events)
        return {"status": "success", "predictions": results}
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict_action")
def predict_single_action(request: ActionRequest):
    """Single-state policy action prediction (used by Streamlit UI).

    If no state_vector is provided, generates a mock 64-d vector
    and returns the PPO policy's recommended action.
    """
    import numpy as np

    if not predictor or not predictor.ready:
        # Return mock response when model is not loaded
        return {
            "action": "QueryEDR",
            "target": request.alert_id or "unknown",
            "confidence_score": 0.0,
            "impact_assessment": "Model not loaded — returning default action.",
            "counterfactuals": [],
        }

    try:
        if request.state_vector:
            state = np.array(request.state_vector, dtype=np.float32)
        else:
            state = np.random.randn(64).astype(np.float32)

        action = predictor.algo.compute_single_action(state)
        action_map = {
            0: "QueryEDR",
            1: "QueryAD",
            2: "CheckThreatIntel",
            3: "ExamineFirewall",
            4: "TerminateAndOutputVerdict",
        }

        return {
            "action": action_map.get(int(action), "Unknown"),
            "target": request.alert_id or "unknown",
            "confidence_score": float(np.linalg.norm(state)) / 10.0,
            "impact_assessment": f"PPO policy recommends {action_map.get(int(action))}.",
            "counterfactuals": [
                {"step": i, "impact_taken": 10 + i * 2, "impact_ignored": 10 + i * 30}
                for i in range(4)
            ],
        }
    except Exception as e:
        logger.error(f"Action prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/trigger_investigation")
def trigger_investigation(trigger: InvestigationTrigger):
    """Webhook endpoint for AlertEngine (Section IV-C).

    Called when a host exceeds the sliding-window threshold.
    """
    logger.info(
        f"Investigation triggered: node={trigger.node_id}, "
        f"events={trigger.event_count}, window={trigger.time_window}s"
    )
    # In production, this would queue the host for HetGAT encoding + PPO evaluation.
    return {"status": "queued", "node_id": trigger.node_id}


@app.post("/train")
def trigger_training(background_tasks: BackgroundTasks):
    """Asynchronously trigger model retraining."""

    def run_training_and_reload():
        success = train_model()
        if success:
            global predictor
            predictor = ThreatPredictor()
            logger.info("Retraining complete. Model reloaded into memory.")

    background_tasks.add_task(run_training_and_reload)
    return {"status": "processing", "message": "Model training started in background."}


if __name__ == "__main__":
    import uvicorn

    from src.config import Config

    uvicorn.run(app, host=Config.API_HOST, port=Config.API_PORT)
