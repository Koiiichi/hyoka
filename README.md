<p>
<svg width="180" height="45" viewBox="0 0 560 140" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="hyoka wordmark">
  <g transform="translate(28,20) scale(0.5)"><polygon points="142.4,57.6 25.8,96.5 103.5,174.2" fill="#0A0A0A"/></g>
  <text x="130" y="90" font-family="'Space Grotesk','Segoe UI',sans-serif" font-weight="600" font-size="58" letter-spacing="-1.5" fill="#0A0A0A">hyoka</text>
</svg>
</p>

> **An open-ended SOC threat-hunting evaluation for `gemini-3.5-flash`.**
> Seven tasks, each a no-hint SQLite database of real Windows attack telemetry from OTRF
> Security-Datasets, scored by F1 against Sigma/behaviour-derived ground truth.
> **0% pass@3 on every task.** Aggregate mean F1 = 0.119 across 35 trials.

---

## Quick start

```bash
# run oracle (expect reward 1.0)
harbor run -p samples/<task-name>/ -a oracle

# run the model under test (5 trials)
BATCH=$(tooling/run_trials.sh samples/<task-name>/ gemini/gemini-3.5-flash 5)
python3 tooling/parse_results.py "$BATCH"

# regenerate the report
python3 report/build_report.py   # writes report/report.html + report/report.pdf
```

---

## Directory structure

```
hyōka/
├── samples/                    # ← the deliverable: 7 fully-built Harbor tasks
│   ├── threat-hunt-windows-eventlogs/
│   ├── lateral-movement-psexec-hunt/
│   ├── persistence-run-key-hunt/
│   ├── discovery-account-enum-hunt/
│   ├── execution-vbs-launcher-hunt/
│   ├── defense-evasion-injection-hunt/
│   └── privesc-uac-bypass-hunt/
│       ├── instruction.md          # agent-facing, no ground-truth leak
│       ├── task.toml               # Harbor schema 1.3
│       ├── environment/
│       │   ├── Dockerfile          # builds the SQLite DB, strips source
│       │   ├── data/
│       │   │   ├── build_inputs.py     # deterministic OTRF loader + obfuscator
│       │   │   └── raw/                # vendored OTRF recording (gzipped JSONL)
│       │   └── skills/             # non-answer-revealing reference material
│       ├── tests/
│       │   ├── test.sh             # Harbor verifier entry-point (writes reward.txt)
│       │   ├── test_outputs.py     # fractional F1 pytest suite
│       │   ├── score_reward.py     # standalone reward printer
│       │   └── ground_truth.json   # hidden event-id set (never shipped in image)
│       └── solution/
│           ├── solve.sh            # real oracle (genuine detection logic)
│           └── lazy_baselines/     # adversarial dumb-solver battery (QA gate)
│
├── logs/
│   └── pilots/                 # ← the 7 pilot batches (5 trials each, 35 total)
│       └── <task>__<batch>/
│
├── report/
│   ├── report.html             # ← the report (open in browser or print to PDF)
│   ├── report.pdf              # print-ready PDF
│   ├── build_report.py         # regenerates report from logs/pilots/
│   ├── analyze_results.py      # pass@k computation
│   └── figures/                # exported SVGs and CSV summary
│
├── tooling/                    # scripts for running and evaluating trials
│   ├── run_trials.sh           # launches N parallel harbor runs
│   ├── parse_results.py        # aggregates pass@k from a batch directory
│   ├── lazy_baseline_probe.py  # QA gate: proves lazy baselines fail
│   └── scratchpad_init.py
│
├── assets/                     # hyōka visual identity
│   ├── wordmark-light.svg
│   ├── wordmark-dark.svg
│   ├── mark.svg / mark-dark.svg
│   └── mark-light-256.png / mark-dark-256.png
│
├── docs/                       # project documentation and reference material
│   ├── AGENTS.md               # task-authoring rules (non-negotiable bar)
│   ├── ROADMAP.md              # task design log and lessons learned
│   └── task-implementation-rubric.toml
│
├── discarded/                  # ← 6 hand-authored tasks that flash solved (93–100%)
│   │                              kept for transparency; excluded from deliverable
│   └── ...
│
├── archive/                    # ← raw Harbor job output and side projects
│   ├── jobs-all/               # every harbor run ever executed locally
│   └── restaurant-weekly-cost-control-audit/
│
├── .env                        # GEMINI_API_KEY (gitignored)
├── .gitignore
└── README.md                   # this file
```

---

## The seven tasks

| Task | ATT&CK tactic | OTRF source | GT events | mean F1 |
|---|---|---|---|---|
| threat-hunt-windows-eventlogs | Credential access + C2 | empire_mimikatz_logonpasswords | 37 | 0.132 |
| lateral-movement-psexec-hunt | Lateral movement | empire_psexec_dcerpc_tcp_svcctl | 4 | 0.199 |
| persistence-run-key-hunt | Persistence | empire_persistence_registry_run_keys | 11 | 0.069 |
| discovery-account-enum-hunt | Discovery | empire net_localgroup + net_local_users | 14 | 0.021 |
| execution-vbs-launcher-hunt | Execution | empire_launcher_vbs | 5 | 0.144 |
| defense-evasion-injection-hunt | Defense evasion | covenant_lolbin_wuauclt_createremotethread | 3 | 0.106 |
| privesc-uac-bypass-hunt | Privilege escalation | empire_uac_shellapi_fodhelper | 7 | 0.164 |

Data: [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (GPL-3.0),
deterministically time-shifted and entity-obfuscated. Ground truth from
[SigmaHQ](https://github.com/SigmaHQ/sigma) detection rules, never shipped inside the
container image.

---

## QA gates (every task must pass before piloting)

```bash
# 1. Lazy-baseline gate — oracle passes, every dumb solver fails
python3 tooling/lazy_baseline_probe.py samples/<task-name>/

# 2. No-output check — verifier fails cleanly without findings.json
TASK_ROOT=$(mktemp -d) python3 samples/<task-name>/environment/data/build_inputs.py
cd samples/<task-name>/tests && python3 -m pytest test_outputs.py -q

# 3. F1 table
bash samples/<task-name>/solution/solve.sh      # writes findings.json
python3 samples/<task-name>/tests/score_reward.py   # should print 1.0000
```

---

## Research grounding

| Source | Relevance |
|---|---|
| [Cyber Defense Benchmark](https://arxiv.org/abs/2604.19533) (arXiv 2604.19533) | Direct precedent; reports flash failing hard on the same task type |
| [CTI-REALM](https://arxiv.org/abs/2603.13517) (arXiv 2603.13517, Microsoft) | Headroom justification; best model 0.637 |
| [CVE-Bench](https://arxiv.org/abs/2503.17332) (arXiv 2503.17332) | Offensive boundary we did not cross |

See `report/report.html` (§3) for the full literature section.

---

## License

Task code: MIT. Vendored telemetry (`samples/*/environment/data/raw/`): GPL-3.0
(OTRF Security-Datasets).
