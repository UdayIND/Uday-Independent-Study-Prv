"""
SENTINEL-RL Policy Training Pipeline.

Trains a Proximal Policy Optimization (PPO) agent using Ray RLlib
on the SentinelInvestigationEnv.

Hyperparameters are loaded from configs/sentinel_rl.yaml (Table I).
CLI arguments override YAML values when provided.
"""

import argparse
import logging
from pathlib import Path

import ray
import yaml
from ray.rllib.algorithms.ppo import PPOConfig
from ray.tune.registry import register_env

from src.config import Config
from src.model.env import SentinelInvestigationEnv

logger = logging.getLogger(__name__)

CONFIG_PATH = Path("configs/sentinel_rl.yaml")


def load_training_config() -> dict:
    """Load PPO hyperparameters from sentinel_rl.yaml."""
    defaults = {
        "train_batch_size_per_learner": 4000,
        "minibatch_size": 128,
        "num_epochs": 10,
        "lr": 5e-5,
        "clip_param": 0.2,
        "entropy_coeff": 0.01,
        "gamma": 0.99,
        "lambda_": 0.95,
        "num_iterations": 200,
        "num_seeds": 5,
    }

    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f)
        ppo = cfg.get("strategic_plane", {}).get("ppo", {})
        defaults.update({k: v for k, v in ppo.items() if v is not None})
        logger.info(f"Loaded training config from {CONFIG_PATH}")
    else:
        logger.warning(f"{CONFIG_PATH} not found — using built-in defaults")

    return defaults


def env_creator(env_config):
    return SentinelInvestigationEnv(config=env_config)


def train_model(num_iterations: int = 2, num_seeds: int = 1, seed: int = 42):
    """Train the PPO policy and save the checkpoint.

    Args:
        num_iterations: Number of training iterations (paper uses 200).
        num_seeds: Number of independent training seeds (paper uses 5).
        seed: Base random seed for reproducibility.

    Returns:
        True if training succeeded.
    """
    logger.info("Initializing Ray for PPO Training...")

    if not ray.is_initialized():
        ray.init(ignore_reinit_error=True)

    register_env("SentinelEnv-v0", env_creator)

    # Load hyperparameters from sentinel_rl.yaml (Table I)
    hparams = load_training_config()

    config = (
        PPOConfig()
        .environment("SentinelEnv-v0")
        .framework("torch")
        .training(
            train_batch_size_per_learner=hparams["train_batch_size_per_learner"],
            minibatch_size=hparams["minibatch_size"],
            num_epochs=hparams["num_epochs"],
            lr=hparams["lr"],
            clip_param=hparams["clip_param"],
            entropy_coeff=hparams["entropy_coeff"],
            gamma=hparams["gamma"],
            lambda_=hparams["lambda_"],
        )
        .env_runners(num_env_runners=1)
        .debugging(seed=seed)
    )

    logger.info("Building PPO Algorithm...")
    algo = config.build()

    logger.info(f"Training for {num_iterations} iterations (seed={seed})...")

    for i in range(num_iterations):
        result = algo.train()
        mean_return = result.get("env_runners", {}).get("episode_reward_mean", float("nan"))
        logger.info(f"Iteration {i + 1}/{num_iterations}: Mean Episode Return = {mean_return:.2f}")

    # Save checkpoint (must be absolute path for PyArrow compatibility)
    save_dir = (Config.MODEL_SAVE_DIR / "ppo_policy_checkpoint").resolve()
    save_dir.mkdir(parents=True, exist_ok=True)

    checkpoint_path = algo.save(str(save_dir))
    logger.info(f"PPO Policy saved to {checkpoint_path}")

    ray.shutdown()
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL-RL PPO Training")
    parser.add_argument(
        "--num-iterations",
        type=int,
        default=None,
        help="Number of training iterations (default: from sentinel_rl.yaml, paper: 200)",
    )
    parser.add_argument(
        "--num-seeds",
        type=int,
        default=None,
        help="Number of independent seeds (default: from sentinel_rl.yaml, paper: 5)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Base random seed for reproducibility",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    # CLI overrides > YAML values > built-in defaults
    hparams = load_training_config()
    num_iterations = args.num_iterations or hparams.get("num_iterations", 2)
    num_seeds = args.num_seeds or hparams.get("num_seeds", 1)

    for s in range(num_seeds):
        current_seed = args.seed + s
        logger.info(f"=== Seed {s + 1}/{num_seeds} (seed={current_seed}) ===")
        train_model(
            num_iterations=num_iterations,
            num_seeds=num_seeds,
            seed=current_seed,
        )
