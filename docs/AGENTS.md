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
6. Before calling any task done, run these four checks locally in plain
   Python (Docker not required for this step) and show the output:
   - Oracle output -> verifier: must pass every check.
   - No output file at all: must fail cleanly (assertion, not a crash).
   - A "dump every plausible finding" attempt: must fail on the
     false-positive check.
   - **The lazy-baseline gate:** `python3 scripts/lazy_baseline_probe.py
     samples/<task-name>/` must exit 0. This runs every "dumbest solve that
     could work" in `solution/lazy_baselines/` (grep one token, flag-all-X)
     and proves each scores 0. If any lazy baseline passes the verifier, the
     signal is separable by that one heuristic and the task is too easy —
     redesign the data, do not just retighten the verifier.
7. **The signal must not be separable by a single surface feature.** This is
   the check the first three miss and the reason easy tasks pass local review
   then get ~100% pass@3. The malicious events and the decoy must be
   *identical* along every greppable dimension (filename, status code,
   user-agent, path token, contiguous burst) and separable ONLY by a computed
   relationship across the artifacts (IP not in trusted CIDRs, endpoint
   knowable only from a second artifact, volume vs. baseline, field
   combination). If a payload names itself (`shell.php`), if the attacker is
   the only non-browser UA, or if the whole chain is one contiguous IP block,
   `grep` beats the task. cloudtrail-privilege-escalation-hunt is the positive
   example: its decoys share the exact `eventName` tokens with the attack, so
   only a CIDR/volume/cross-context relationship separates them. Encode that
   exact lazy solve as a lazy baseline (item 6) and prove it fails.

## Harbor task.toml schema (confirmed against harborframework.com/docs, 2026-07)

Use `schema_version = "1.3"`. Task identity/authorship goes under `[task]`
(`name`, `description`, `authors`, `keywords`), not `[metadata]` —
`[metadata]` is free-form (we use it for `difficulty_explanation` and
`category`). See the reference task's `task.toml` for the exact working shape.

**Network mode — local development vs. final delivery:**
`network_mode = "no-network"` is the correct final-delivery setting (closes
the web-search cheat path), but Harbor's Docker environment on macOS does not
support it — the egress-control capability requires Linux kernel primitives
not exposed by Docker Desktop. Use `allow_internet = true` for all tasks
during local authoring and piloting. Replace it with `network_mode =
"no-network"` only when packaging for final submission. Every task in
`samples/` should currently have `allow_internet = true` in its
`[environment]` block and no `network_mode` key.

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
    lazy_baselines/   # >=1 adversarial "dumbest solve" script (*.sh/*.py) — the gate proves each scores 0
```

**Local-sandbox convention (required for the lazy-baseline gate).**
`build_inputs.py`, `solve.sh`, and `test_outputs.py` must all honor a
`TASK_ROOT` environment variable that defaults to `/root`. In the container
nothing sets it, so behavior is identical to hardcoding `/root`; locally the
probe points it at a temp dir so the task can be built and graded without
Docker. Read it as `Path(os.environ.get("TASK_ROOT", "/root"))` in Python and
`ROOT="${TASK_ROOT:-/root}"` in shell.

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
