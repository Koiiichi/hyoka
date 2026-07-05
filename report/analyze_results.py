"""
Aggregate Harbor `jobs/` output into pass@1 / pass@3 per task, plus an overall
difficulty-curve plot.

Usage:
    uv run analyze_results.py --jobs-dir logs/jobs --out-dir report/figures

Walks every trial-level result.json under --jobs-dir (identified by the
presence of a "verifier_result" key, to distinguish trial results from the
job-level rollup result.json), groups by task_name, and computes:

  - pass@1: mean(pass indicator) across all trials for that task
  - pass@3: the standard unbiased pass@k estimator from the Codex/HumanEval
    paper -- pass@k = 1 - C(n-c, k) / C(n, k) -- using whatever k you pass
    (default 3), computed from however many trials you actually ran (>=k).

A trial "passes" if verifier_result.rewards.reward >= --pass-threshold
(default 1.0). Override per-task if a task uses a fractional or numeric
reward where 1.0 isn't the right bar -- see PASS_THRESHOLD_OVERRIDES below.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path

# Per-task overrides for what counts as a "pass," for tasks using fractional
# (F1-style) or numeric-tolerance rewards rather than strict binary 0/1.
# Fill these in as you build tasks 2-8, e.g.:
#   "sigma-rule-authoring-c2-beacon": 0.8,
PASS_THRESHOLD_OVERRIDES: dict[str, float] = {}

DEFAULT_PASS_THRESHOLD = 1.0


def find_trial_results(jobs_dir: Path):
    for result_path in jobs_dir.rglob("result.json"):
        try:
            data = json.loads(result_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if "verifier_result" in data:  # trial-level, not the job-level rollup
            yield result_path, data


def extract_reward(trial_data: dict) -> float | None:
    vr = trial_data.get("verifier_result") or {}
    rewards = vr.get("rewards") or {}
    if not rewards:
        return None
    # Take "reward" if present, else the first value in the dict.
    if "reward" in rewards:
        return float(rewards["reward"])
    return float(next(iter(rewards.values())))


def pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased pass@k estimator (Chen et al. 2021 / HumanEval / Codex paper)."""
    if n - c < k:
        return 1.0
    return 1.0 - math.prod((n - c - i) / (n - i) for i in range(k)) if k > 0 else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs-dir", type=Path, required=True, help="Root dir containing Harbor job output (e.g. logs/jobs)")
    parser.add_argument("--out-dir", type=Path, default=Path("report/figures"), help="Where to write the CSV + plot")
    parser.add_argument("--k", type=int, default=3, help="k for pass@k (default 3, per the brief)")
    args = parser.parse_args()

    by_task: dict[str, list[float]] = defaultdict(list)

    for _, data in find_trial_results(args.jobs_dir):
        task_name = data.get("task_name")
        reward = extract_reward(data)
        if task_name is None or reward is None:
            continue
        by_task[task_name].append(reward)

    if not by_task:
        raise SystemExit(f"No trial result.json files with a verifier_result found under {args.jobs_dir}")

    args.out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for task_name, rewards in sorted(by_task.items()):
        threshold = PASS_THRESHOLD_OVERRIDES.get(task_name, DEFAULT_PASS_THRESHOLD)
        passes = [1 if r >= threshold else 0 for r in rewards]
        n, c = len(passes), sum(passes)
        p1 = c / n if n else 0.0
        p_at_k = pass_at_k(n, c, args.k) if n >= args.k else None
        rows.append(
            {
                "task_name": task_name,
                "n_trials": n,
                "n_pass": c,
                "pass@1": round(p1, 3),
                f"pass@{args.k}": round(p_at_k, 3) if p_at_k is not None else None,
                "clears_bar_lt_30pct": (p_at_k is not None and p_at_k < 0.30),
            }
        )

    # CSV
    csv_path = args.out_dir / "pass_at_k_summary.csv"
    header = list(rows[0].keys())
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write(",".join(header) + "\n")
        for row in rows:
            f.write(",".join(str(row[h]) for h in header) + "\n")

    print(f"Wrote {csv_path}")
    for row in rows:
        flag = "OK (<30%)" if row["clears_bar_lt_30pct"] else "TOO EASY -- rework or cut"
        print(f"  {row['task_name']:<40} n={row['n_trials']:<3} pass@1={row['pass@1']:<6} pass@{args.k}={row[f'pass@{args.k}']:<6} [{flag}]")

    # Difficulty-curve plot
    try:
        import matplotlib.pyplot as plt

        plotted = [r for r in rows if r[f"pass@{args.k}"] is not None]
        if plotted:
            plotted.sort(key=lambda r: r[f"pass@{args.k}"])
            names = [r["task_name"] for r in plotted]
            vals = [r[f"pass@{args.k}"] for r in plotted]
            colors = ["#d62728" if v >= 0.30 else "#2ca02c" for v in vals]

            fig, ax = plt.subplots(figsize=(9, max(3, 0.5 * len(names))))
            ax.barh(names, vals, color=colors)
            ax.axvline(0.30, color="black", linestyle="--", linewidth=1, label="30% target ceiling")
            ax.set_xlabel(f"pass@{args.k} vs gemini-3.5-flash")
            ax.set_xlim(0, 1)
            ax.set_title("Per-task difficulty (lower = harder, red = fails the <30% bar)")
            ax.legend(loc="lower right")
            fig.tight_layout()
            fig_path = args.out_dir / "difficulty_curve.png"
            fig.savefig(fig_path, dpi=150)
            print(f"Wrote {fig_path}")
    except ImportError:
        print("matplotlib not installed -- skipping plot (uv add matplotlib to enable it)")


if __name__ == "__main__":
    main()
