"""
Fractional reward scorer for the sigma-rule-authoring-c2-beacon task.

Loads the agent's Sigma rule from ``$TASK_DATA_ROOT/sigma_rule.yml``, evaluates
it against the held-out labeled corpus in ``sigma_eval``, and writes the F1
score (the task reward) to ``/logs/verifier/reward.txt``. A missing file,
unparseable YAML, or a rule that matches nothing all yield reward 0.0.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sigma_eval

RULE_FILE = Path(os.environ.get("TASK_DATA_ROOT", "/root")) / "sigma_rule.yml"
REWARD_DIR = Path(os.environ.get("VERIFIER_LOG_DIR", "/logs/verifier"))


def main() -> None:
    """Compute the F1 reward and write it to the verifier reward file."""
    if not RULE_FILE.exists():
        metrics = {"f1": 0.0, "precision": 0.0, "recall": 0.0,
                   "tp": 0, "fp": 0, "fn": 0, "error": "missing sigma_rule.yml"}
    else:
        metrics = sigma_eval.f1_for_rule_text(RULE_FILE.read_text(encoding="utf-8"))

    reward = round(float(metrics["f1"]), 6)
    REWARD_DIR.mkdir(parents=True, exist_ok=True)
    (REWARD_DIR / "reward.txt").write_text(f"{reward}\n", encoding="utf-8")

    print(json.dumps({"reward": reward, **metrics}, indent=2))


if __name__ == "__main__":
    main()
