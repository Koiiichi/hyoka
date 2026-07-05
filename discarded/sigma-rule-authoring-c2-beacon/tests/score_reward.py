#!/usr/bin/env python3
"""
Compute the fractional reward (held-out F1) for a submitted Sigma rule and print
it. test.sh writes this value to /logs/verifier/reward.txt so the reward is the
F1 score (0.0-1.0), while test_outputs.py enforces the binary pass threshold.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
import sigma_verifier  # noqa: E402

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
RULE_FILE = TASK_ROOT / "sigma_rule.yml"


def main() -> None:
    try:
        import yaml
        rule = yaml.safe_load(RULE_FILE.read_text(encoding="utf-8"))
        result = sigma_verifier.score(rule)
        print(f"{result['f1']:.4f}")
    except Exception:
        print("0.0000")


if __name__ == "__main__":
    main()
