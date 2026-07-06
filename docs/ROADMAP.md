# Hyoka — Roadmap

**Slice:** SOC threat-hunting / detection engineering from raw telemetry — defensive
security, ETL + correlation shaped, no offensive-exploit-execution tasks.

**Why this slice:** it is directly validated by the literature as an unsolved,
high-headroom capability. Microsoft's CTI-REALM (Mar 2026) is a benchmark for
exactly this workflow — turn threat intelligence into validated detections against
real telemetry — and even frontier models plateau well below solved (best of 16
models: Claude Opus 4.6 (High) 0.637 overall reward). The slice is also a good fit
for deterministic, reproducible Harbor tasks.

## How difficulty is sourced (the rule this roadmap now follows)

The take-home brief is explicit: "you're graded on whether you find a real failure
mode and design samples that isolate it ... Try recreating tasks from their evals —
frontier benchmarks are a cheat-code for finding failure modes that haven't been
solved yet, and SOTA plateaus tell you where to dig." Difficulty is **inherited from
a cited plateau, not estimated by intuition.**

Earlier versions of this roadmap named a hard benchmark to justify the *domain* but
then invented *static, single-shot* tasks that stripped out the mechanics that make
those benchmarks hard. The pilots proved the cost: cloudtrail (which happens to
retain a real failure mode) sits at 0/3, while the invented static tasks land at
93-100% pass@3. Every task below now records the specific source, its measured
plateau, and the difficulty-bearing mechanic it must reproduce.

### Verified headroom anchors (checked against primary sources, 2026-07)

- **CTI-REALM** — arXiv 2603.13517, Microsoft, Mar 2026. 37 real CTI reports
  (Microsoft, Datadog, Palo Alto, Splunk); 50-task suite across Linux endpoints,
  AKS, and Azure cloud. Interactive, tool-rich: read a report, explore a telemetry
  schema, iterate KQL queries against live telemetry, emit Sigma + KQL detections.
  Scored on **final detection quality AND intermediate checkpoints** (report
  selection, MITRE technique mapping, data-source identification, query refinement).
  Best of 16 models: Opus 4.6 (High) 0.637, Opus 4.5 0.624; GPT-5 family behind.
  Per platform: **Linux 0.585 -> AKS 0.517 -> Cloud 0.282** (cloud multi-source
  correlation is the hardest sub-problem). Removing CTI tools costs up to 0.150.
- **CVE-Bench** — arXiv 2503.17332, UIUC, 2025 (one of the brief's two named
  starting points). Real critical-severity CVEs in runnable web apps, sandboxed,
  **execution-based verifier** (did the exploit actually achieve its effect).
  SOTA agent framework resolves **up to 13%**. Repo: uiuc-kang-lab/cve-bench.
- **SEVRA-BENCH** — arXiv 2606.13757, Jun 2026. 1,062 malicious PRs built by
  **inverting real CVE-fix commits** to restore the vulnerable code, wrapped in 15
  social-engineering framings, across the top-10 CWE Top-25. Review-agent must
  reject; "sharp gap between closed- and open-source models." This is the
  properly-hard form of our "diff introduces a vuln" idea.
- **VulnRepairEval** — arXiv 2509.03331. Exploit-based vuln-repair eval; top model
  fixes only 5/23 (~21.7%).
- **Automated Web Vulnerability Reproduction** — arXiv 2510.14700. Agents "consistently
  fail on complex service-based vulnerabilities requiring multi-component
  environments" — a documented, nameable failure mode.

### Design principles that follow from these plateaus

1. **Anchor to a cited plateau.** Every task states its source and SOTA number; that
   number is the headroom claim, not a guess.
2. **Recreate the mechanic, not the theme.** The difficulty in the anchors comes from
   interactive schema exploration + iterative execution (CTI-REALM), execution-based
   verification against a runnable target (CVE-Bench), or an adversarial ground-truth
   decision (SEVRA-BENCH). A static "parse a synthetic file -> emit a set" recreation
   discards exactly the part the model fails.
3. **Prefer fractional and/or multi-axis scoring.** CTI-REALM scores intermediate
   checkpoints; our one hard survivor (cloudtrail) fails frontier-adjacent models on a
   *second* axis (per-event MITRE labels), not just the event set. A single-axis exact
   set match is the weakest verifier and the easiest to pass.
4. **Lean into cloud multi-source correlation.** Empirically the hardest sub-problem
   (CTI-REALM Cloud 0.282). cloudtrail is the template.
5. **Keep the lazy-baseline gate as a floor, not a ceiling.** `scripts/lazy_baseline_probe.py`
   proves a task is not grep-solvable; it does NOT prove the task is hard. Passing the
   gate is necessary, not sufficient — a task can be grep-resistant and still within
   flash's one-shot reasoning (see web-shell v2).

Note on reward scales: CTI-REALM/CVE-Bench report fractional/execution rewards; our
deliverable bar is <30% pass@3 for gemini-3.5-flash. These are not the same metric —
the anchors establish that the *capability* is unsolved at the frontier, which makes
a flash-tier model plausibly far below 30% when the mechanic is preserved.

### Sharpened finding (after re-piloting tasks 3 and 5)

Recreating the *mechanic* of a hard benchmark at small, clean, synthetic scale is
NOT sufficient to reproduce its difficulty. web-shell v2 (diff + response-size
correlation) and sigma v2 (train/test generalization + hard negatives + iteration
harness) are both faithful mechanic recreations, both pass the lazy-baseline gate,
and both are still solved by gemini-3.5-flash at ~100% pass@3 — the sigma pilot
converged on a robust, generalizing multi-field rule using the intended reasoning.

The headroom in CTI-REALM (0.637) and CVE-Bench (13%) does not come from the
mechanic type; it comes from properties our synthetic tasks strip out:
  - **Scale and open-endedness.** 37 real messy CTI reports, a large unknown
    telemetry schema to explore, many candidate techniques/data-sources. Our tasks
    collapse to a low-dimensional puzzle (one beacon, one clean 8-column CSV, ~5
    fields all visible) that a capable model closes in a few iterations.
  - **Real-world messiness.** Real CTI reports / real CVEs / real repos, not
    clean deterministic generators with a single planted signal.
  - **Execution-based or multi-stage/multi-axis grading.** CVE-Bench requires an
    exploit that actually fires; CTI-REALM scores intermediate checkpoints. Our
    single-artifact set/F1 match passes on one correct guess. cloudtrail (the only
    task under 30%) is the exception precisely because it adds a second axis
    (per-event MITRE label) over a messier event space.

Conclusion: stop trying to make clean synthetic single-signal tasks hard by hiding
the signal. Difficulty for a capable model requires (a) real or realistically-messy
large-scale inputs, (b) a large search space, and (c) execution-based or multi-axis
scoring. This is a change in approach, not another round of signal-hiding.

---

## Task 1 — BUILT: `auth-log-lateral-movement-hunt`

Reference pattern; oracle/nop/false-positive checks pass. **Anchor:** ExCyTIn-Bench /
CTI-REALM investigation stage (multi-host threat investigation).
**Status/risk:** static single-shot, single-axis (host/timestamp set + lenient MITRE).
Headroom is unproven — must be piloted against flash; if it clears 30%, add the
cloudtrail treatment (second scoring axis, non-eyeball-able correlation) or demote.

## Candidates — re-anchored

| # | Task | Source anchor (failure mode) | Measured plateau | Difficulty mechanic to inherit | Current status |
|---|---|---|---|---|---|
| 2 | `cloudtrail-privilege-escalation-hunt` | CTI-REALM cloud-correlation (2603.13517); cloud IAM abuse | Cloud platform **0.282** (best model) | CIDR/volume/cross-context correlation the model can't eyeball + **2nd axis (MITRE label per event)** | **0/3 was an ARTIFACT, not a win.** All 3 trials got the exact event set right (solved the correlation) and failed only on ONE label: a `ListBucket` event the answer key marks T1530, which flash labelled T1083 (Discovery) -- flash's answer is defensible / arguably more correct. Ground-truth bug. Not a genuine capability gap. |
| 3 | `sigma-rule-authoring-c2-beacon` | CTI-REALM Sigma-rule generation (2603.13517) | Best overall **0.637**; sub-platform lower | Give a **telemetry schema to explore + iterative query execution**; score held-out F1 against **hard negatives that share one behavioral field**; fractional reward | **REBUILT to CTI-REALM mechanics** (train/test split: authored on network A, graded on hidden network B with rotated C2 domains, beacon variants, and two single-field hard negatives; iteration harness `sigma_eval.py`; fractional F1 reward, pass=F1 1.0). Oracle F1=1.0; every single-field/domain/literal lazy baseline <1.0; lazy-baseline gate passes. **Re-piloted: still 5/5 pass@3 (F1=1.0).** flash used the iteration harness and built a robust multi-field generalizing rule. Recreating the mechanic was not enough — see "Sharpened finding" below. |
| 4 | `alert-queue-triage-ranking` | ExCyTIn-Bench / alert-fatigue triage | (no clean single number — treat as unproven) | Evidence that requires cross-referencing, not ranking salient snippets; 2nd axis (justification/technique) | **100% pass@3 — too easy.** Rework or cut. |
| 5 | `web-shell-forensics-log-and-patch` | **SEVRA-BENCH** (2606.13757) + CVE-Bench (2503.17332); cloudtrail Lever-A recipe | SEVRA closed/open gap; CVE-Bench **13%**; cloudtrail **0/3** | **Rebuilt to Lever A**: heterogeneous 8-step intrusion (brute force -> valid accounts -> exploit upload -> web shell -> cred access -> discovery -> tool transfer -> archive -> exfil), exact request-id set **+ per-request MITRE family** (accept-sets), 4 heterogeneous decoys. ~16 independent must-all-be-right decisions. | **REBUILT (Lever A). Piloted 0/5 — but this is an AMBIGUITY ARTIFACT, not genuine difficulty.** Trajectories show flash produced all 8 chain events with correct technique families AND excluded all 4 decoys; it failed only by additionally flagging the 6 failed brute-force login attempts (a defensible T1110 answer) and tripping the >12 over-broad guard. Done fairly (disambiguate failed-attempt scope either way), flash solves it. Conclusion: Lever A did not defeat flash; do not ship as a win. Re-audit cloudtrail's 0/3 for the same artifact. |
| 6 | `insider-threat-storage-exfil` | Cloud storage exfil detection (CTI-REALM cloud family) | Cloud **0.282** as proxy | Numeric threshold-crossing over a noisy baseline the model must actually compute; tolerance-banded | Not built. Design to the numeric-plus-baseline mechanic. |
| 7 | `dns-exfiltration-tunnel-detection` | DNS tunnelling detection; multi-component env failure (2510.14700) | Service-based multi-component failure mode | A real **decode step** + generalization to held-out domains; numeric byte estimate | Not built. The decode step is the difficulty — keep it. |
| 8 | `incident-report-claim-verification` | Contradiction detection over multi-modal I/O (brief's PDF hint) | (unproven — pilot) | **PDF** claim vs. raw logs that contradict it; evidence citation as a 2nd axis | Not built. Natural fit for the brief's multi-modal ask. |
| 9 | `vulnerable-file-service-patch` | **CVE-Bench (2503.17332, ~13%) / VulnRepairEval (2509.03331, ~21.7%)** | Execution SOTA 13-22% | **Execution-based**: patch a runnable service; verifier RUNS a security suite (multi-vector traversal) + a functional suite; pass only if both fully pass. Defensive/synthetic per AGENTS.md (no offensive exploit). | Built; **piloted 5/5 (too easy)** — single canonical CWE (path traversal) has a memorized one-liner fix (safe_join). Superseded by task 10. |
| 10 | `api-security-audit-and-fix` | **CVE-Bench / VulnRepairEval + audit multiplicity** | Execution SOTA 13-22% | **Lever B, execution-based, multiplicative, NO ambiguous axis**: THREE distinct vulns (IDOR, mass-assignment privesc, SSTI) in one runnable service; hidden suite runs each exploit + functional cases; reward 1 only if ALL pass. | **Piloted 5/5 (flash fixed all three) — too easy.** Confirms hand-authored synthetic tasks, even multiplicative/execution-based, are within flash's competence. Cut. |
| 11 | `credential-dump-hunt` | **Cyber Defense Benchmark (arXiv 2604.19533)** over **OTRF Security-Datasets** | Best model **~3.8%** of malicious events; Gemini 3 Flash fails hard | **Lever B, REAL DATA**: a real Empire+Mimikatz recording (6,026 real Windows Security/Sysmon events), deterministically time-shifted + entity-obfuscated, in a SQLite DB. Hunt with NO hints; flag malicious events (37: C2 beacons + lsass reads, 0.6%). Objective F1 vs Sigma/behaviour-derived ground truth. | **BUILT + locally verified.** Oracle F1=1.0; all lazy hunts fail (0.01-0.55); gate passes; answer source stripped from image. **PILOTED: 0/5 pass@3; F1 = [0.015, 0.60, 0.015, 0.015, 0.015], mean ~0.13. GENUINE difficulty — differentiated scores (not an artifact), matches arXiv 2604.19533's flash result. Trajectories: flash finds the malicious process GUID but cannot precisely delimit the 37 events; 4/5 over-flag (precision collapse), 1/5 partial. VALIDATED — the template for the suite.** |

**Direction going forward:** hand-authored synthetic tasks (1, 3, 4, 5, 9, 10) are all within gemini-3.5-flash's competence and should be cut or kept only as easy-end anchors. The suite's headroom comes from Lever B: real OTRF recordings wrapped as no-hint threat-hunts scored objectively (task 11 pattern). Scale to the target 5-10 tasks by wrapping additional OTRF procedures (different tactics/techniques) with the same builder + Sigma-derived ground truth -- which is also the report's scale-plan answer.

## Curation bar (unchanged targets, stronger gates)

Drop or rework anything that:
- Doesn't clear <30% pass@3 against gemini-3.5-flash after real trials.
- Oracle doesn't score 1.0 cleanly, or nop scores above 0.
- A "dump everything" / "flag nothing" strategy passes.
- **Fails the lazy-baseline gate** (`scripts/lazy_baseline_probe.py` must exit 0).
- **Is not anchored to a cited plateau** with a difficulty mechanic reproduced from
  the source — an intuition-difficult task is the documented failure mode of this repo.

## Timeline

1. **Re-anchor + rebuild the too-easy tasks (3, 4, 5)** to their source mechanics
   before adding new ones; cloudtrail is the template.
2. **Author remaining candidates (6-8)** directly to a cited anchor + mechanic.
3. **`harbor check -r`** each task against the TB3 rubric.
4. **Pilot:** oracle + nop + lazy-baseline gate, then >=5 `gemini/gemini-3.5-flash`
   trials per task (3 cannot distinguish 0% from ~33%).
5. **Curate to 5-10** on the pass@3 bar and task-design cleanliness.
6. **Pull trajectories** on failures for the failure-analysis section (confirm failures
   are genuine difficulty, not task-design bugs).
7. **Write the report**; the research-awareness section now has real citations to draw
   from (CTI-REALM, CVE-Bench, SEVRA-BENCH, VulnRepairEval, 2510.14700).
8. **Package and send** — `samples/ logs/ report/`, correct email subject line.


## Validated OTRF threat-hunt suite (the real deliverable)

All built to the confirmed template (real OTRF Security-Datasets recording, deterministic
time-shift + entity-obfuscation into a SQLite DB, no-hint hunt, Sigma/behaviour-derived
ground truth, fractional F1). Every one: oracle 1.0, nop 0.0, pass@3 = 0%, differentiated
scores = genuine difficulty (not artifacts). Source generator + labels stripped from the
runtime image; GPL-3.0 OTRF data vendored with attribution.

| Task | OTRF source | Malicious set | pass@3 | Trial F1s | Dominant failure mode |
|---|---|---|---|---|---|
| `credential-dump-hunt` | empire_mimikatz_logonpasswords | 37 (C2 beacons + lsass reads) | 0% | 0.015,0.015,0.015,0.284,0.015 | precision collapse (recall 1.0 all trials, flagged 224-4871) |
| `psexec-lateral-hunt` | empire_psexec_dcerpc_tcp_svcctl | 4 (cross-source: 4624+4697+7045+Sysmon1) | 0% | 0.276,0.012,0.296,0.216,0.333 | precision collapse (recall 1.0 all trials, flagged 20-644) |
| `run-key-hunt` | empire ...run_keys_elevated_user | 11 (run-key + C2 beacons) | 0% | 0.069,0.063,0.068,0.074,0.069 | precision collapse (recall 1.0 all trials, flagged 287-337) |
| `account-enumeration-hunt` | empire net_localgroup + net_local_users | 14 (net.exe recon + 4798/4799) | 0% | 0.020,0.014,0.020,0.323,0.020 | cross-source recall gap (4/5 trials) + over-flag; one trial partially correlated |
| `vbs-launcher-hunt` | empire_launcher_vbs | 5 (script-host process tree + C2 network) | 0% | 0.313,0.008,0.010,0.385,0.435 | precision collapse (recall 1.0 all trials, flagged 18-1183) |
| `lolbin-injection-hunt` | covenant_lolbin_wuauclt_createremotethread | 3 (Sysmon 1 LOLBin + 7 non-Windows DLL + 8 CreateRemoteThread) | 0% | 0.019,0.122,0.022,0.057,0.30 | precision collapse (found chain, over-flag) |
| `uac-bypass-hunt` | empire_uac_shellapi_fodhelper | 7 (ms-settings\Run-command registry hijack + fodhelper + child) | 0% | 0.318,0.389,0.008,0.226,0.389 | precision collapse (recall 1.0 all trials, flagged 29-1839) |

Failure-analysis themes for the report (all from real trajectories): (1) precision collapse
-- the model locates the malicious events but cannot prune benign context (recall high,
precision near zero); (2) cross-source recall gap -- it catches one log source's fragment
and misses the correlated evidence in another; (3) partial-chain near-misses. These are
genuine reasoning/scoping failures over real high-volume telemetry, matching arXiv 2604.19533.

Scale plan (report answer): the suite grows mechanically by wrapping more OTRF procedures
(other tactics/techniques) through the same builder + Sigma-derived ground truth.
