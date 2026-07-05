#!/usr/bin/env python3
"""parse_results.py — parse a batch directory produced by run_trials.sh.

Reads result.json files from each trial_N/ subdirectory, computes pass rate,
and writes a summary to stdout as JSON. Exits 0 if pass_rate < 0.30 (task
is hard enough), exits 1 if pass_rate >= 0.30 (task needs tightening).

Usage:
    python3 scripts/parse_results.py <batch-dir> [--pass-threshold 0.30]

Typical use in a /goal loop:
    BATCH=$(scripts/run_trials.sh samples/my-task/)
    python3 scripts/parse_results.py "$BATCH"
    # exit code tells the agent whether to tighten or declare done
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional


RESULT_FILENAME = "result.json"
POLL_TIMEOUT_SECONDS = 15
POLL_INTERVAL = 0.5


def wait_for_result(result_path: Path) -> dict:
    """Poll until result.json is non-empty and valid JSON, or raise TimeoutError."""
    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            text = result_path.read_text()
            data = json.loads(text)
            if data:
                return data
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        time.sleep(POLL_INTERVAL)
    raise TimeoutError(
        f"Result not ready after {POLL_TIMEOUT_SECONDS}s: {result_path}"
    )


def extract_score(result: dict) -> Optional[float]:
    """Extract the reward score from a Harbor trial-level result.json payload.

    Harbor stores the score at verifier_result.rewards.reward in the
    trial-level result.json (the one nested under <timestamp>/<trial-name>/).
    Older or job-level result.json files use a different schema and will
    return None, which the caller treats as an invalid trial.
    """
    verifier = result.get("verifier_result")
    if not verifier:
        return None
    rewards = verifier.get("rewards")
    if not rewards:
        return None
    score = rewards.get("reward")
    return float(score) if score is not None else None


def parse_batch(batch_dir: str, pass_threshold: float) -> dict:
    """Parse all trial results under batch_dir and return a summary dict."""
    batch_path = Path(batch_dir)
    if not batch_path.is_dir():
        raise FileNotFoundError(f"Batch directory not found: {batch_path}")

    trial_dirs = sorted(batch_path.glob("trial_*"))
    if not trial_dirs:
        raise FileNotFoundError(f"No trial_* subdirectories found in {batch_path}")

    scores = []
    errors = []

    for trial_dir in trial_dirs:
        # Harbor layout: trial_N/<timestamp>/<trial-name>/result.json
        # Two wildcards needed to reach the trial-level result.json.
        candidates = sorted(trial_dir.glob(f"*/*/{RESULT_FILENAME}"))
        if not candidates:
            stderr_log = trial_dir / "stderr.log"
            error_detail = "no result.json found"
            if stderr_log.exists():
                tail = stderr_log.read_text().strip().splitlines()
                error_detail = tail[-1] if tail else error_detail
            errors.append({"trial": trial_dir.name, "error": error_detail})
            scores.append(None)
            continue

        result_path = candidates[-1]
        try:
            result = wait_for_result(result_path)
            score = extract_score(result)
            scores.append(score)
        except TimeoutError as exc:
            errors.append({"trial": trial_dir.name, "error": str(exc)})
            scores.append(None)

    valid_scores = [s for s in scores if s is not None]
    passes = sum(1 for s in valid_scores if s >= 1.0)
    pass_rate = passes / len(scores) if scores else 0.0
    needs_tightening = pass_rate >= pass_threshold

    return {
        "batch_dir": str(batch_path),
        "total_trials": len(scores),
        "valid_trials": len(valid_scores),
        "scores": scores,
        "passes": passes,
        "pass_rate": round(pass_rate, 4),
        "pass_threshold": pass_threshold,
        "needs_tightening": needs_tightening,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch_dir", help="Batch directory from run_trials.sh")
    parser.add_argument(
        "--pass-threshold",
        type=float,
        default=0.30,
        help="Pass rate at or above which tightening is required (default: 0.30)",
    )
    args = parser.parse_args()

    summary = parse_batch(args.batch_dir, args.pass_threshold)
    print(json.dumps(summary, indent=2))

    if summary["errors"]:
        print(
            f"\nWARNING: {len(summary['errors'])} trial(s) had errors:",
            file=sys.stderr,
        )
        for err in summary["errors"]:
            print(f"  {err['trial']}: {err['error']}", file=sys.stderr)

    # Exit 1 signals "needs tightening" to the calling shell or /goal agent.
    sys.exit(1 if summary["needs_tightening"] else 0)


if __name__ == "__main__":
    main()
