"""
SENTINEL-RL / SOC-Informed Discovery API Backend.
Serves model inference and exposes training endpoints via FastAPI.
"""

import logging
from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel

from src.model.inference import ThreatPredictor
from src.model.train import train_model

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SENTINEL-RL SOC API",
    description="Real-time inference backend for Agentic SOC threat detection.",
    version="0.1.0",
)

# Initialize Predictor lazily on startup
predictor: ThreatPredictor = None

@app.on_event("startup")
def load_model():
    global predictor
    logger.info("Initializing ThreatPredictor...")
    predictor = ThreatPredictor()
    if not predictor.ready:
        logger.warning("Predictor failed to load model. /predict endpoint will fail until /train is triggered.")

class EventPayload(BaseModel):
    events: List[Dict[str, Any]]

@app.get("/health")
def health_check():
    """System health check endpoint."""
    return {"status": "ok", "model_loaded": predictor.ready if predictor else False}

@app.post("/predict")
def predict_threats(payload: EventPayload):
    """
    Predict threat likelihood for a batch of events.
    Returns a list of source IPs with their anomaly risk scores.
    """
    if not predictor or not predictor.ready:
        raise HTTPException(status_code=503, detail="Model not loaded. Trigger training first.")
        
    try:
        results = predictor.predict(payload.events)
        return {"status": "success", "predictions": results}
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/train")
def trigger_training(background_tasks: BackgroundTasks):
    """
    Asynchronously trigger model retraining using the latest normalized data.
    """
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
