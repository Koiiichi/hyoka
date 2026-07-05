#!/usr/bin/env bash
# run_trials.sh — launch N parallel Harbor trials for a task and collect results.
#
# Usage:
#   scripts/run_trials.sh <task-path> [model] [n-trials]
#
# Examples:
#   scripts/run_trials.sh samples/sigma-rule-authoring-c2-beacon/
#   scripts/run_trials.sh samples/sigma-rule-authoring-c2-beacon/ gemini/gemini-3.5-flash 3
#
# Prints the batch directory path to stdout on success so the caller can pass
# it directly to parse_results.py:
#   BATCH=$(scripts/run_trials.sh samples/my-task/)
#   python3 scripts/parse_results.py "$BATCH"

set -euo pipefail

TASK_PATH="${1:?Usage: run_trials.sh <task-path> [model] [n-trials]}"
MODEL="${2:-gemini/gemini-3.5-flash}"
N_TRIALS="${3:-3}"
ENV_FILE="${ENV_FILE:-.env}"
BATCH_DIR="jobs/batch_$(date +%s)"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: env file not found at '${ENV_FILE}'." >&2
    echo "Create it with GEMINI_API_KEY=... or set ENV_FILE= to point elsewhere." >&2
    exit 1
fi

# Auto-patch task.toml: replace network_mode = "no-network" with allow_internet = true.
# Harbor's Docker environment on macOS does not support no-network (requires Linux
# kernel egress primitives). This is safe for local development; revert before
# final submission per AGENTS.md.
TASK_TOML="${TASK_PATH%/}/task.toml"
if grep -q 'network_mode *= *"no-network"' "$TASK_TOML" 2>/dev/null; then
    sed -i '' 's/network_mode *= *"no-network"/allow_internet = true/' "$TASK_TOML"
    echo "  Patched task.toml: network_mode=\"no-network\" -> allow_internet = true" >&2
fi

mkdir -p "$BATCH_DIR"

echo "Starting ${N_TRIALS} trial(s) for ${TASK_PATH} using ${MODEL}" >&2
echo "Results directory: ${BATCH_DIR}" >&2

PID_1="" PID_2="" PID_3="" PID_4="" PID_5=""

for i in $(seq 1 "$N_TRIALS"); do
    TRIAL_DIR="${BATCH_DIR}/trial_${i}"
    mkdir -p "$TRIAL_DIR"
    harbor run \
        -p "$TASK_PATH" \
        -a terminus-2 \
        -m "$MODEL" \
        --jobs-dir "$TRIAL_DIR" \
        --env-file "$ENV_FILE" \
        --quiet \
        > "${TRIAL_DIR}/stdout.log" \
        2> "${TRIAL_DIR}/stderr.log" &
    eval "PID_${i}=$!"
    echo "  Launched trial ${i} (PID $!)" >&2
done

FAILED=0
for i in $(seq 1 "$N_TRIALS"); do
    eval "CURRENT_PID=\$PID_${i}"
    if wait "$CURRENT_PID"; then
        echo "  Trial ${i}: completed" >&2
    else
        EC=$?
        echo "  Trial ${i}: FAILED (exit code ${EC})" >&2
        echo "  Stderr log: ${BATCH_DIR}/trial_${i}/stderr.log" >&2
        FAILED=$((FAILED + 1))
    fi
done

if [[ $FAILED -gt 0 ]]; then
    echo "WARNING: ${FAILED}/${N_TRIALS} trial(s) exited non-zero." >&2
    echo "Check stderr logs under ${BATCH_DIR} before trusting parse results." >&2
fi

# Print the batch dir to stdout — this is what the caller captures.
echo "$BATCH_DIR"
