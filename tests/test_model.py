"""Tests for the SENTINEL-RL strategic plane components."""

import numpy as np

from src.model.env import SentinelInvestigationEnv


def test_env_creation():
    """Test that the environment can be instantiated."""
    env = SentinelInvestigationEnv()
    assert env.action_space.n == 5
    assert "obs" in env.observation_space.spaces
    assert env.observation_space.spaces["obs"].shape == (64,)
    assert env.observation_space.spaces["action_mask"].shape == (5,)


def test_env_reset():
    """Test that reset returns a valid observation."""
    env = SentinelInvestigationEnv()
    obs, info = env.reset(seed=42)
    assert "obs" in obs
    assert obs["obs"].shape == (64,)
    assert obs["obs"].dtype == np.float32
    assert "action_mask" in obs
    assert obs["action_mask"][4] == 0  # Terminate is masked initially
    assert isinstance(info, dict)


def test_env_step():
    """Test that step returns valid outputs for a non-terminal action."""
    env = SentinelInvestigationEnv()
    env.reset(seed=42)
    obs, reward, terminated, truncated, info = env.step(0)  # QueryEDR
    assert "obs" in obs
    assert obs["obs"].shape == (64,)
    assert reward == -0.01  # Small negative cost per step
    assert terminated is False
    assert info["action_taken"] == 0


def test_env_terminate_action():
    """Test that TerminateAndOutputVerdict (action=4) terminates the episode."""
    env = SentinelInvestigationEnv()
    env.reset(seed=42)
    obs, reward, terminated, truncated, info = env.step(4)
    assert terminated is True
    assert info["action_taken"] == 4


def test_env_truncation():
    """Test that the episode truncates after max_steps."""
    env = SentinelInvestigationEnv()
    env.reset(seed=42)
    for i in range(9):
        obs, reward, terminated, truncated, info = env.step(0)
        assert truncated is False
    # Step 10 should truncate
    obs, reward, terminated, truncated, info = env.step(0)
    assert truncated is True


def test_env_gymnasium_compliance():
    """Test that the env passes Gymnasium's check_env (basic contract)."""
    env = SentinelInvestigationEnv()
    obs, info = env.reset()
    assert env.observation_space.contains(obs)
    action = env.action_space.sample()
    obs, reward, terminated, truncated, info = env.step(action)
    assert env.observation_space.contains(obs)
    assert isinstance(reward, (int, float))
    assert isinstance(terminated, bool)
    assert isinstance(truncated, bool)
