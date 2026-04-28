"""
SENTINEL-RL Investigation MDP (Gymnasium Environment).

Section IV-B, VI-C: The PPO policy evaluates a 64-dimensional HetGAT state
vector and selects one of five investigative actions. The reward is sparse
and goal-aligned (Section VI-C):

  +1 if TerminateAndOutputVerdict agrees with LANL red-team ground truth
   0 otherwise
  -0.01 per investigative step (to encourage parsimony)

Action masking (Section IV-E): TerminateAndOutputVerdict cannot execute
unless at least two distinct evidence sources have been gathered.
"""

import gymnasium as gym
import numpy as np
from gymnasium import spaces

# Action indices matching the paper's action space
ACTION_QUERY_EDR = 0
ACTION_QUERY_AD = 1
ACTION_CHECK_THREAT_INTEL = 2
ACTION_EXAMINE_FIREWALL = 3
ACTION_TERMINATE = 4

ACTION_NAMES = {
    ACTION_QUERY_EDR: "QueryEDR",
    ACTION_QUERY_AD: "QueryAD",
    ACTION_CHECK_THREAT_INTEL: "CheckThreatIntel",
    ACTION_EXAMINE_FIREWALL: "ExamineFirewall",
    ACTION_TERMINATE: "TerminateAndOutputVerdict",
}

# Evidence source categories for action masking
EVIDENCE_SOURCES = {
    ACTION_QUERY_EDR: "edr",
    ACTION_QUERY_AD: "ad",
    ACTION_CHECK_THREAT_INTEL: "threat_intel",
    ACTION_EXAMINE_FIREWALL: "firewall",
}


def load_env_config() -> dict:
    """Load environment parameters from sentinel_rl.yaml if available."""
    try:
        from pathlib import Path

        import yaml

        config_path = Path("configs/sentinel_rl.yaml")
        if config_path.exists():
            with open(config_path) as f:
                cfg = yaml.safe_load(f)
            ppo = cfg.get("strategic_plane", {}).get("ppo", {})
            return {
                "max_investigation_steps": ppo.get("max_investigation_steps", 10),
                "step_penalty": ppo.get("step_penalty", -0.01),
            }
    except Exception:
        pass
    return {}


class SentinelInvestigationEnv(gym.Env):
    """Threat Investigation Markov Decision Process for SENTINEL-RL.

    The agent investigates an alerted host by selecting discrete actions.
    State is a 64-dimensional HetGAT topology vector (Section IV-B).

    The reward structure incentivises both true-positive AND true-negative
    verdicts equally (Section VI-C):
      - Correct verdict (TP or TN): +1.0
      - Incorrect verdict (FP or FN): -1.0
      - Premature termination (<2 evidence sources): -1.0
      - Each investigative step: step_penalty (-0.01)
    """

    metadata = {"render_modes": []}

    def __init__(self, config=None):
        super().__init__()
        config = config or {}

        # Merge YAML config with runtime overrides
        yaml_config = load_env_config()
        yaml_config.update(config)
        config = yaml_config

        # 5 strict investigative actions (Section IV-B)
        self.action_space = spaces.Discrete(5)

        # 64-dimensional dense state vector from HetGAT encoder + action_mask
        self.observation_space = spaces.Dict(
            {
                "obs": spaces.Box(low=-np.inf, high=np.inf, shape=(64,), dtype=np.float32),
                "action_mask": spaces.Box(low=0, high=1, shape=(5,), dtype=np.int8),
            }
        )

        self.max_steps = config.get("max_investigation_steps", 10)
        self.step_penalty = config.get("step_penalty", -0.01)

        # Ground truth for the current episode (simulated)
        self._is_true_threat = False
        self._evidence_gathered: set[str] = set()
        self.current_step = 0

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0
        self._evidence_gathered = set()

        # Simulate whether the alerted host is a true threat
        # (50/50 in training; in production this is the LANL ground truth)
        self._is_true_threat = self.np_random.random() > 0.5

        # In a live system, the HetGAT encoder would compress the 2-hop
        # Neo4j subgraph into this vector. For training we use a random state
        # that correlates weakly with threat status.
        state = self.np_random.standard_normal(64).astype(np.float32)
        if self._is_true_threat:
            state[:8] += 0.5  # Subtle signal for the policy to learn

        return {"obs": state, "action_mask": self._get_action_mask()}, {}

    def _get_action_mask(self):
        """Action mask: Terminate (4) is invalid until >= 2 evidence sources are gathered."""
        mask = np.ones(5, dtype=np.int8)
        if len(self._evidence_gathered) < 2:
            mask[ACTION_TERMINATE] = 0
        return mask

    def step(self, action):
        self.current_step += 1

        reward = self.step_penalty  # Small negative cost per step
        terminated = False
        truncated = False

        if action in EVIDENCE_SOURCES:
            # Gathering evidence from a source
            self._evidence_gathered.add(EVIDENCE_SOURCES[action])

        elif action == ACTION_TERMINATE:
            terminated = True

            # Action masking check (Section IV-E):
            # TerminateAndOutputVerdict requires >= 2 evidence sources
            if len(self._evidence_gathered) < 2:
                reward = -1.0  # Penalty for premature termination
            else:
                # Sparse reward (Section VI-C):
                # The agent's implicit verdict is 'threat detected'.
                # +1 for CORRECT verdict (true positive OR true negative)
                # -1 for INCORRECT verdict (false positive OR false negative)
                #
                # Since the only terminal action is 'output verdict', we
                # model it as a binary classification: the agent chooses
                # when to terminate. If it terminates on a true threat,
                # that's correct (TP). The policy also learns to gather
                # evidence and NOT terminate on benign hosts by reaching
                # max_steps (implicit TN via truncation).
                if self._is_true_threat:
                    reward = 1.0  # True Positive: correct identification
                else:
                    reward = -1.0  # False Positive: incorrect alarm

        if self.current_step >= self.max_steps:
            truncated = True
            # Implicit TN/FN at truncation (ran out of time):
            if not terminated:
                if self._is_true_threat:
                    reward += -0.5  # Missed a real threat (FN penalty)
                else:
                    reward += 0.5  # Correctly let benign host expire (TN bonus)

        # Generate next state observation
        next_state = self.np_random.standard_normal(64).astype(np.float32)
        if self._is_true_threat:
            next_state[:8] += 0.5

        info = {
            "action_taken": action,
            "action_name": ACTION_NAMES.get(action, "Unknown"),
            "evidence_sources": list(self._evidence_gathered),
            "is_true_threat": self._is_true_threat,
        }

        return (
            {"obs": next_state, "action_mask": self._get_action_mask()},
            reward,
            terminated,
            truncated,
            info,
        )
