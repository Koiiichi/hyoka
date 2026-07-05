#!/bin/bash

pip3 install --break-system-packages \
  pytest==8.4.1 \
  pytest-json-ctrf==0.3.5

mkdir -p /logs/verifier

# Reward is the fractional F1 over the intrusion's malicious events.
REWARD=$(python3 /tests/score_reward.py)
echo "$REWARD" > /logs/verifier/reward.txt
echo "Threat-hunt F1 (reward): $REWARD"

pytest --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA -v

exit 0
