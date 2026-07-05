#!/usr/bin/env python3
"""
sigma_eval.py -- iterate on your Sigma rule against the visible proxy logs.

Usage:
    python3 /root/data/sigma_eval.py /root/sigma_rule.yml [--show N]

Applies your rule to /root/data/proxy_logs.csv and reports how many rows it
matches, with a sample. This mirrors running a detection query against
telemetry so you can refine before finalizing. It does NOT reveal any labels or
the held-out set your rule is graded on -- a rule that fits these logs must
still generalize.
"""
from __future__ import annotations

import argparse
import csv
import os
import re
from pathlib import Path

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML is required: pip install pyyaml")

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
LOG = TASK_ROOT / "data" / "proxy_logs.csv"


def apply_modifier(field_value, mod, target) -> bool:
    fv, tv = str(field_value), str(target)
    if mod in ("", "equals"):
        return fv == tv
    if mod == "contains":
        return tv in fv
    if mod == "startswith":
        return fv.startswith(tv)
    if mod == "endswith":
        return fv.endswith(tv)
    if mod == "re":
        try:
            return re.search(tv, fv) is not None
        except re.error:
            return False
    return False


def match_field(event, key, target) -> bool:
    parts = key.split("|")
    field = parts[0]
    mod = parts[1] if len(parts) > 1 else ""
    if field not in event:
        return False
    values = target if isinstance(target, list) else [target]
    return any(apply_modifier(event[field], mod, v) for v in values)


def match_block(event, block) -> bool:
    return isinstance(block, dict) and all(match_field(event, k, v) for k, v in block.items())


def eval_condition(condition, block_bools) -> bool:
    c = str(condition).strip().lower()
    if c in ("1 of them", "1 of selection*"):
        return any(block_bools.values())
    if c == "all of them":
        return all(block_bools.values())
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789_ ()*")
    if any(ch not in allowed for ch in c):
        return False
    ns = {k.lower(): bool(v) for k, v in block_bools.items()}
    try:
        return bool(eval(c, {"__builtins__": {}}, ns))
    except Exception:
        return False


def match_event(rule, event) -> bool:
    detection = rule["detection"]
    blocks = {k: v for k, v in detection.items() if k != "condition"}
    bools = {name: match_block(event, blk) for name, blk in blocks.items()}
    return eval_condition(detection["condition"], bools)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("rule_path")
    ap.add_argument("--show", type=int, default=10)
    args = ap.parse_args()

    rule = yaml.safe_load(Path(args.rule_path).read_text(encoding="utf-8"))
    if not isinstance(rule, dict) or "detection" not in rule:
        raise SystemExit("Rule must be a mapping with a 'detection' block.")

    matched = 0
    total = 0
    shown = 0
    with LOG.open() as f:
        for event in csv.DictReader(f):
            total += 1
            if match_event(rule, event):
                matched += 1
                if shown < args.show:
                    print(f"  MATCH {event['timestamp']} {event['src_host']} "
                          f"{event['dst_domain']} {event['uri_path']} ua={event['user_agent'][:40]}...")
                    shown += 1

    print(f"\nMatched {matched} of {total} rows in proxy_logs.csv.")
    print("Reminder: your rule is graded on a hidden held-out network with different "
          "domains and look-alikes. Fitting these rows is necessary but not sufficient.")


if __name__ == "__main__":
    main()
