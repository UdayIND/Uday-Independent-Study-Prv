"""
Central Configuration Manager for SOC-Informed Discovery.
Loads environment variables from .env if available, providing typed config objects.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file (if present)
load_dotenv()

class Config:
    """Base Configuration parameters."""
    
    # API Settings
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    API_ENV: str = os.getenv("API_ENV", "development")
    
    # Neo4j Settings
    NEO4J_URI: str = os.getenv("NEO4J_URI", "neo4j://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "password")
    
    # Kafka Settings
    KAFKA_BROKER: str = os.getenv("KAFKA_BROKER", "localhost:9092")
    KAFKA_TOPIC: str = os.getenv("KAFKA_TOPIC", "network_events")
    KAFKA_GROUP_ID: str = os.getenv("KAFKA_GROUP_ID", "sentinel_ingestion_group")
    
    # Model Directories
    MODEL_SAVE_DIR: Path = Path(os.getenv("MODEL_SAVE_DIR", "data/models"))
    MODEL_VERSION: str = os.getenv("MODEL_VERSION", "latest")
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    @classmethod
    def setup(cls):
        """Ensure critical directories exist."""
        cls.MODEL_SAVE_DIR.mkdir(parents=True, exist_ok=True)

# Run setup on import to ensure directories are created
Config.setup()
