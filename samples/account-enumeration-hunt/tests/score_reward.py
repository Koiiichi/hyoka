#!/usr/bin/env python3
"""Compute the fractional reward (F1 of flagged malicious events) and print it.
test.sh writes this to /logs/verifier/reward.txt."""
from __future__ import annotations

import json
import os
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
OUTPUT_FILE = TASK_ROOT / "findings.json"
GROUND_TRUTH = Path(__file__).parent / "ground_truth.json"


def extract_id(item):
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        for k in ("event_id", "id", "eventid"):
            if k in item:
                return str(item[k]).strip()
    return ""


def main():
    try:
        raw = json.loads(OUTPUT_FILE.read_text(encoding="utf-8"))
        submitted = {extract_id(x) for x in raw if extract_id(x)}
        truth = set(json.loads(GROUND_TRUTH.read_text(encoding="utf-8")))
        tp = len(submitted & truth)
        precision = tp / len(submitted) if submitted else 0.0
        recall = tp / len(truth) if truth else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        print(f"{f1:.4f}")
    except Exception:
        print("0.0000")


if __name__ == "__main__":
    main()
