#!/usr/bin/env python3
"""lazy_baseline_probe.py -- the "can a dumb solver beat this task?" gate.

The existing sanity checks (oracle passes, nop fails, dump-everything fails)
verify that the *intended* solution works and that the verifier rejects an
over-broad answer. They do NOT verify that a lazy, single-feature solver
FAILS. That blind spot is how tasks that `grep <one token>` can solve still
pass local review and then get ~100% pass@3 in piloting.

This probe closes that gap. For a given task it:
  1. Builds the task inputs into a temp TASK_ROOT (no Docker needed).
  2. Runs the real oracle and scores it with the task's own verifier -- this
     must PASS (sanity; a broken task is caught here).
  3. Runs every lazy baseline the author encoded under
     solution/lazy_baselines/ and scores each with the same verifier -- every
     one must FAIL.

A task PASSES the gate only if the oracle passes and every lazy baseline
fails. If any lazy baseline passes, the task's signal is separable by that
dumb heuristic and the task is under-specified: redesign the data so the true
positives and the decoys are identical along that surface feature.

Requirements on the task (the local-sandbox convention):
  - environment/data/build_inputs.py, solution/solve.sh, and
    tests/test_outputs.py must all honor a TASK_ROOT environment variable
    (defaulting to /root) so the task can be built and graded outside Docker.
  - The author must provide at least one lazy baseline under
    solution/lazy_baselines/ (a *.sh or *.py script that writes the task's
    output file using a deliberately dumb heuristic). Without one, the gate
    cannot run and the task is not done.

Usage:
    python3 scripts/lazy_baseline_probe.py samples/<task-name>/

Exit codes:
    0  gate passed (oracle passes, all lazy baselines fail)
    1  gate failed (a lazy baseline passed -> task too easy)
    2  probe could not run (missing TASK_ROOT support, no baselines, oracle
       did not pass, etc.)
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run_script(script: Path, task_root: Path) -> subprocess.CompletedProcess:
    """Execute a generator/oracle/baseline script with TASK_ROOT set."""
    env = dict(os.environ)
    env["TASK_ROOT"] = str(task_root)
    if script.suffix == ".py":
        cmd = ["python3", str(script)]
    else:
        cmd = ["bash", str(script)]
    return subprocess.run(cmd, env=env, capture_output=True, text=True)


def score_with_verifier(task_path: Path, task_root: Path) -> bool:
    """Run the task's pytest verifier against the current output. True == pass.

    Runs from inside tests/ so a non-ASCII repo path cannot break pytest's
    file-argument matching.
    """
    tests_dir = task_path / "tests"
    env = dict(os.environ)
    env["TASK_ROOT"] = str(task_root)
    proc = subprocess.run(
        ["python3", "-m", "pytest", "test_outputs.py", "-q"],
        cwd=str(tests_dir),
        env=env,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def top_level_files(task_root: Path) -> set[str]:
    """Names of regular files directly under TASK_ROOT (i.e. output files)."""
    return {p.name for p in task_root.iterdir() if p.is_file()}


def clear_outputs(task_root: Path, output_names: set[str]) -> None:
    """Remove known output files so each baseline starts from a clean slate."""
    for name in output_names:
        target = task_root / name
        if target.exists():
            target.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task_path", help="Path to the task directory (samples/<task-name>/)")
    args = parser.parse_args()

    task_path = Path(args.task_path).resolve()
    generator = task_path / "environment" / "data" / "build_inputs.py"
    oracle = task_path / "solution" / "solve.sh"
    # Lazy baselines are dev/QA artifacts kept out of the shipped task dir (they
    # are not required to build/run/solve/verify the task). They live alongside
    # this probe under tooling/lazy_baselines/<task-name>/.
    baselines_dir = Path(__file__).resolve().parent / "lazy_baselines" / task_path.name

    if not generator.exists():
        print(f"FATAL: generator not found: {generator}", file=sys.stderr)
        return 2
    if not oracle.exists():
        print(f"FATAL: oracle not found: {oracle}", file=sys.stderr)
        return 2

    baseline_scripts = []
    if baselines_dir.is_dir():
        baseline_scripts = sorted(
            p for p in baselines_dir.iterdir()
            if p.is_file() and p.suffix in (".sh", ".py")
        )
    if not baseline_scripts:
        print(
            f"FATAL: no lazy baselines found under {baselines_dir}.\n"
            "The gate is meaningless without the author encoding at least one "
            "'dumbest solve that could work' (e.g. grep a single token). "
            "Add one or more *.sh/*.py scripts there and rerun.",
            file=sys.stderr,
        )
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="lazy_probe_"))
    try:
        task_root = tmp
        (task_root / "data").mkdir(parents=True, exist_ok=True)

        # Step 1: build inputs.
        gen = run_script(generator, task_root)
        if gen.returncode != 0:
            print("FATAL: generator failed. Does build_inputs.py honor TASK_ROOT?", file=sys.stderr)
            print(gen.stderr, file=sys.stderr)
            return 2

        before = top_level_files(task_root)

        # Step 2: oracle must PASS.
        orc = run_script(oracle, task_root)
        if orc.returncode != 0:
            print("FATAL: oracle script errored. Does solve.sh honor TASK_ROOT?", file=sys.stderr)
            print(orc.stderr, file=sys.stderr)
            return 2
        output_names = (top_level_files(task_root) - before) or {"findings.json"}
        oracle_pass = score_with_verifier(task_path, task_root)

        # Step 3: every lazy baseline must FAIL.
        results = []
        for script in baseline_scripts:
            clear_outputs(task_root, output_names)
            proc = run_script(script, task_root)
            output_names |= (top_level_files(task_root) - before)
            errored = proc.returncode != 0
            passed = score_with_verifier(task_root=task_root, task_path=task_path) if not errored else False
            results.append((script.name, errored, passed))

        # Report.
        print("=" * 68)
        print(f"LAZY-BASELINE GATE: {task_path.name}")
        print("=" * 68)
        print(f"  oracle -> verifier: {'PASS' if oracle_pass else 'FAIL'}  (must PASS)")
        print("  lazy baselines (each must FAIL the verifier):")
        for name, errored, passed in results:
            if errored:
                verdict = "errored (counts as fail-to-solve, OK)"
            elif passed:
                verdict = "PASSED VERIFIER  <-- task is beatable by this dumb solver"
            else:
                verdict = "failed verifier (good)"
            print(f"    - {name:32s} {verdict}")
        print("-" * 68)

        any_baseline_passed = any(passed for _, _, passed in results)
        if not oracle_pass:
            print("VERDICT: BROKEN -- the oracle does not pass its own verifier.")
            return 2
        if any_baseline_passed:
            print("VERDICT: GATE FAILED -- a lazy baseline solved the task. Redesign the")
            print("         data so true positives and decoys share that surface feature.")
            return 1
        print("VERDICT: GATE PASSED -- oracle passes, every lazy baseline fails.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
