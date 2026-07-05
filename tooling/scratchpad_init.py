#!/usr/bin/env python3
"""scratchpad_init.py — initialize or reset a scratchpad.json for a task.

The scratchpad is the agent's state carrier across tightening cycles. Writing
state here instead of reasoning inline keeps the context window clean.

Usage:
    python3 scripts/scratchpad_init.py <task-path>
    python3 scripts/scratchpad_init.py samples/sigma-rule-authoring-c2-beacon/

Creates <task-path>/scratchpad.json. If one already exists, it is overwritten
(use this to reset between benchmark runs).
"""

import argparse
import json
import sys
from pathlib import Path


INITIAL_SCRATCHPAD = {
    "task_path": "",
    "cycle": 0,
    "oracle_score": None,
    "nop_score": None,
    "trials": [],
    "pass_threshold": 0.30,
    "tightening_actions": [],
    "exit_condition_met": False,
    "failure_reason": None,
}


def init_scratchpad(task_path: str) -> Path:
    """Write a fresh scratchpad.json into task_path and return its path."""
    task_dir = Path(task_path)
    if not task_dir.is_dir():
        raise FileNotFoundError(f"Task directory not found: {task_dir}")

    scratchpad = {**INITIAL_SCRATCHPAD, "task_path": str(task_dir)}
    out_path = task_dir / "scratchpad.json"
    out_path.write_text(json.dumps(scratchpad, indent=2) + "\n")
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task_path", help="Path to the task directory")
    args = parser.parse_args()

    try:
        out_path = init_scratchpad(args.task_path)
        print(f"Initialized scratchpad: {out_path}")
        print(json.dumps(json.loads(out_path.read_text()), indent=2))
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
