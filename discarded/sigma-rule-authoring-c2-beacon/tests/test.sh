#!/bin/bash

pip3 install --break-system-packages \
  pytest==8.4.1 \
  pytest-json-ctrf==0.3.5 \
  pyyaml==6.0.2

mkdir -p /logs/verifier

# Reward is the fractional held-out F1 score.
REWARD=$(python3 /tests/score_reward.py)
echo "$REWARD" > /logs/verifier/reward.txt
echo "Held-out F1 (reward): $REWARD"

# Structured checks and the binary pass threshold (for logs / pass@k).
pytest --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA -v

exit 0
