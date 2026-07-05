# Hyoka — Cybersecurity Detection-Engineering Eval

## What this repo is

We are authoring the **exam**, not the student. The student is Abundant's agent
(`terminus-2` scaffold running `gemini/gemini-3.5-flash`) and Harbor is the
tooling that runs it. This repo contains Harbor-format **tasks** — problem +
sandboxed environment + hidden grading script + answer key — nothing else.
We never write or modify an agent.

Deliverable: 5-10 tasks in `samples/`, `harbor run` logs in `logs/` (>=3
trials per task against gemini-3.5-flash), and a report in `report/`
answering distribution / difficulty-profile / research-awareness / scale-plan
/ failure-analysis.

## Domain slice

SOC threat-hunting / detection engineering from raw telemetry. Real
distribution, not CTF or offensive-exploit tasks. See `ROADMAP.md` for the
full candidate list and rationale.

## The non-negotiable bar (matches `auth-log-lateral-movement-hunt`, the reference task)

1. **The oracle (`solution/solve.sh`) must be a real solver.** It derives its
   answer by parsing/correlating the generated data with generalizable logic
   (regex + time-windowed correlation, or whatever fits the artifact type) —
   never a hardcoded literal of the expected output. If you can't write a
   real detector, the scenario is under-specified; simplify it, don't fake
   the solve script.
2. **The data generator (`environment/data/build_inputs.py` or equivalent)
   must be fully deterministic.** No unseeded randomness — same output on
   every container build, so `tests/test_outputs.py` can hardcode exact
   expected values and stay stable.
3. **Every task needs a decoy** — a benign look-alike of the malicious
   pattern (a typo-then-success login, a scanner that never succeeds, a
   routine backup job that resembles staging, etc.). Without a decoy the task
   is solvable by naive pattern-matching and won't clear the <30% pass@3 bar.
4. **The verifier must reject over-broad answers.** Add an explicit
   excessive-findings / false-positive check (see
   `test_no_excessive_findings` and `test_decoy_scanner_not_flagged` in the
   reference task) so "flag everything plausible" cannot pass.
5. **`instruction.md` is agent-facing only** — never leak ground truth,
   decoy identities, or the exact thresholds used to build the generator.
   A `skills/` reference file is fine (general MITRE ATT&CK lookup, log
   format notes) as long as it doesn't reveal the specific answer.
6. Before calling any task done, run these three checks locally in plain
   Python (Docker not required for this step) and show the output:
   - Oracle output -> verifier: must pass every check.
   - No output file at all: must fail cleanly (assertion, not a crash).
   - A "dump every plausible finding" attempt: must fail on the
     false-positive check.

## Harbor task.toml schema (confirmed against harborframework.com/docs, 2026-07)

Use `schema_version = "1.3"`. Task identity/authorship goes under `[task]`
(`name`, `description`, `authors`, `keywords`), not `[metadata]` —
`[metadata]` is free-form (we use it for `difficulty_explanation` and
`category`). Set `[environment].network_mode = "no-network"` unless a task
genuinely needs egress — our tasks are pure local log/file analysis, so
disabling network is both realistic and closes an obvious cheat path (the
agent searching the web for the answer instead of deriving it). See the
reference task's `task.toml` for the exact working shape.

## File layout convention (mirror this exactly for every new task)

```
samples/<task-name>/
  instruction.md
  task.toml
  environment/
    Dockerfile
    data/            # generator script(s) + any static input files (e.g. asset inventories)
    skills/<skill-name>/SKILL.md   # optional, non-answer-revealing reference material
  tests/
    test.sh           # installs pytest, runs it, writes /logs/verifier/reward.txt
    test_outputs.py
  solution/
    solve.sh          # self-contained: inline the python via `python3 <<'PYTHON_SCRIPT' ... PYTHON_SCRIPT`
```

## Reference materials in this repo

- `samples/auth-log-lateral-movement-hunt/` — the completed, tested pattern.
- `ROADMAP.md` — full candidate list (tasks 2-8), verifier-flavor mix, curation bar.
- `report/analyze_results.py` — run this against `logs/jobs/` once real
  `harbor run` trials exist, to get per-task pass@1/pass@3 and a difficulty plot.

## What NOT to do

- Don't write offensive exploit code, real working malware, or anything
  targeting a real unpatched system. Every scenario here is synthetic and
  defensive-framed.
- Don't invent benchmark numbers, pass rates, or citations for the report —
  if a number isn't derived from an actual `harbor run`, mark it
  `[TODO: run trials]` rather than filling in a plausible-looking guess.
- Do not use emojis anywhere in the codebase unless explicitly instructed.
- The only comments permitted are function docstrings. Keep all docstrings professional and consistent with current standards.
