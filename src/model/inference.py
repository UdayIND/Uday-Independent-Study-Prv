"""
SENTINEL-RL Inference Pipeline.
Loads trained PPO policy to recommend investigation actions.
"""

import logging
from typing import Any

import numpy as np
import ray
from ray.rllib.algorithms.ppo import PPOConfig
from ray.tune.registry import register_env

from src.config import Config
from src.model.env import SentinelInvestigationEnv

logger = logging.getLogger(__name__)


class ThreatPredictor:
    """Loads a trained PPO policy and recommends investigation actions."""

    def __init__(self):
        self.ready = False
        checkpoint_dir = (Config.MODEL_SAVE_DIR / "ppo_policy_checkpoint").resolve()

        if not checkpoint_dir.exists():
            logger.warning(f"Checkpoint directory not found: {checkpoint_dir}")
            return

        # Find the latest checkpoint subfolder
        subdirs = [d for d in checkpoint_dir.glob("checkpoint_*") if d.is_dir()]

        if not subdirs:
            logger.warning("No PPO checkpoint found. Please run the training script.")
            return

        latest_checkpoint = sorted(subdirs)[-1]

        try:
            if not ray.is_initialized():
                ray.init(ignore_reinit_error=True)

            def env_creator(config):
                return SentinelInvestigationEnv(config)

            register_env("SentinelEnv-v0", env_creator)

            # Reconstruct algo from checkpoint
            config = PPOConfig().environment("SentinelEnv-v0").framework("torch")
            self.algo = config.build()
            self.algo.restore(str(latest_checkpoint))

            self.ready = True
            logger.info(f"PPO Policy loaded from {latest_checkpoint}")
        except Exception as e:
            logger.error(f"Failed to load PPO policy: {e}")
            self.ready = False

    def predict(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Recommend threat actions for a batch of events.

        In the full architecture, this would use the HetGAT encoder to
        compress a 2-hop Neo4j subgraph into a 64-d state vector.
        Here we use a random state for demonstration.

        Args:
            events: List of event dictionaries with at least 'src_ip'.

        Returns:
            List of action recommendations with action names and metrics.
        """
        if not self.ready:
            raise RuntimeError("Model is not loaded.")

        results = []
        action_map = {
            0: "QueryEDR",
            1: "QueryAD",
            2: "CheckThreatIntel",
            3: "ExamineFirewall",
            4: "TerminateAndOutputVerdict",
        }

        for event in events:
            src_ip = event.get("src_ip", "unknown")

            # Mock HetGAT extraction (production would call encoder.extract_subgraph_from_neo4j)
            state = np.random.randn(64).astype(np.float32)

            # Predict using PPO
            action = self.algo.compute_single_action(state)

            results.append(
                {
                    "src_ip": src_ip,
                    "action_id": int(action),
                    "action_name": action_map[int(action)],
                    "metrics": {"state_norm": float(np.linalg.norm(state))},
                }
            )

        return results
