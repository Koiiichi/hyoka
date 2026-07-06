# Hyōka — Report

The report is **`report.html`** (open in a browser) — a single, self-contained
document with embedded monochrome SVG figures, rendered in the `hyoka` design
kit (Space Grotesk headers, IBM Plex Mono body). A print-ready **`report.pdf`**
is generated from it.

It answers the brief's five questions:

1. **Distribution** — the slice (open-ended SOC threat hunting over real Windows
   telemetry), what is in/out of scope, and where the data comes from (OTRF
   Security-Datasets, time-shifted + entity-obfuscated; Sigma-derived ground
   truth).
2. **Difficulty profile** — per-task and aggregate pass@1 / pass@3 (0% throughout),
   mean-F1 difficulty curve, and the dominant failure modes, with three figures.
3. **Research awareness** — Cyber Defense Benchmark (2604.19533), CTI-REALM
   (2603.13517), CVE-Bench, SEVRA-BENCH, VulnRepairEval, OTRF, SigmaHQ.
4. **Scale plan** — 7 → 1,000 via the parametric builder, public data sources,
   augmentation, and the automated lazy-baseline QA gate.
5. **Failure analysis** — precision collapse and cross-source recall gaps,
   argued from real trajectories against oracle/nop controls.

Regenerate with: `python3 report/build_report.py` (reads the pilot data;
figures are computed, not hand-drawn).

Supporting artefacts: `figures/` (CSV + standalone SVG), `analyze_results.py`
(pass@k computation), `../logs/pilots/` (raw trials), `../discarded/` (the
hand-authored tasks the model solved, retained for transparency).
