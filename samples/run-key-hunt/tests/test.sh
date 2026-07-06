#!/bin/bash
# Verifier tooling (pytest, pytest-json-ctrf) is baked into tests/Dockerfile;
# nothing is installed here at verify time.

mkdir -p /logs/verifier

# Reward is the fractional F1 over the intrusion's malicious events.
REWARD=$(python3 /tests/score_reward.py)
echo "$REWARD" > /logs/verifier/reward.txt
echo "Threat-hunt F1 (reward): $REWARD"

pytest --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA -v

exit 0
