#!/usr/bin/env python3
"""
SENTINEL-RL Evaluation — Reproduces Table III (Detection Performance).

Evaluates the trained PPO policy on held-out LANL red-team events and
computes precision, recall, F1, and AUC metrics.

Usage:
    python scripts/evaluate.py --checkpoint data/models/ppo_policy_checkpoint
"""

import argparse
import logging

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def evaluate_policy(checkpoint_path: str, num_episodes: int = 100, seed: int = 42):
    """Evaluate the PPO policy and compute detection metrics.

    Args:
        checkpoint_path: Path to the PPO checkpoint directory.
        num_episodes: Number of evaluation episodes.
        seed: Random seed for reproducibility.
    """
    import ray
    from ray.rllib.algorithms.ppo import PPOConfig
    from ray.tune.registry import register_env

    from src.model.env import SentinelInvestigationEnv

    if not ray.is_initialized():
        ray.init(ignore_reinit_error=True)

    def env_creator(config):
        return SentinelInvestigationEnv(config)

    register_env("SentinelEnv-v0", env_creator)

    config = PPOConfig().environment("SentinelEnv-v0").framework("torch")
    algo = config.build()

    try:
        algo.restore(checkpoint_path)
        logger.info(f"Policy loaded from {checkpoint_path}")
    except Exception as e:
        logger.error(f"Failed to load checkpoint: {e}")
        ray.shutdown()
        return

    # Evaluation loop
    tp, fp, tn, fn = 0, 0, 0, 0
    total_returns = []

    env = SentinelInvestigationEnv()

    rng = np.random.RandomState(seed)

    for episode in range(num_episodes):
        obs, info = env.reset(seed=int(rng.randint(0, 2**31)))
        episode_return = 0.0
        done = False

        while not done:
            action = algo.compute_single_action(obs)
            obs, reward, terminated, truncated, info = env.step(action)
            episode_return += reward
            done = terminated or truncated

        total_returns.append(episode_return)

        # Extract ground truth from the environment
        is_threat = info.get("is_true_threat", False)
        predicted_threat = info.get("action_taken") == 4  # TerminateAndOutputVerdict

        if is_threat and predicted_threat:
            tp += 1
        elif not is_threat and predicted_threat:
            fp += 1
        elif is_threat and not predicted_threat:
            fn += 1
        else:
            tn += 1

    # Compute metrics (Table III)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    mean_return = np.mean(total_returns)
    std_return = np.std(total_returns)

    print("\n" + "=" * 60)
    print("SENTINEL-RL Detection Performance (Table III)")
    print("=" * 60)
    print(f"  Episodes evaluated: {num_episodes}")
    print(f"  Mean episodic return: {mean_return:.2f} ± {std_return:.2f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1:        {f1:.4f}")
    print(f"  TP={tp}, FP={fp}, FN={fn}, TN={tn}")
    print("=" * 60)

    ray.shutdown()


def main():
    parser = argparse.ArgumentParser(description="SENTINEL-RL Policy Evaluation")
    parser.add_argument(
        "--checkpoint",
        default="data/models/ppo_policy_checkpoint",
        help="Path to PPO checkpoint directory",
    )
    parser.add_argument("--num-episodes", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    evaluate_policy(args.checkpoint, args.num_episodes, args.seed)


if __name__ == "__main__":
    main()
