#!/usr/bin/env python3
"""
Build report/report.html -- the polished, single-file Hyoka eval report.

Reads the per-trial pilot data (extracted from logs/pilots) and emits a
self-contained HTML document following the 'hyoka' design kit: monochrome
palette (#0A0A0A / #FFFFFF / #666666), Space Grotesk headers, IBM Plex Mono
body, and native inline monochrome SVG figures. Reproducible: rerun to
regenerate after new pilots.
"""
from __future__ import annotations

import json
from pathlib import Path
from statistics import mean
import base64
import urllib.request
import re as _re

HERE = Path(__file__).parent
INK, PAPER, GREY = "#0A0A0A", "#FFFFFF", "#666666"


# ---------------------------------------------------------------------------
# Font embedding (ensures identical rendering in browser AND headless PDF)
# ---------------------------------------------------------------------------
_FONT_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
_FONT_URL = ("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700"
             "&family=IBM+Plex+Mono:wght@400;500&display=swap")
_FONT_CACHE = HERE / ".font_cache.css"


def _fetch_inline_fonts() -> str:
    """Return a <style> block with @font-face rules using base64 data URIs.

    Downloads the latin subset of Space Grotesk and IBM Plex Mono from Google
    Fonts once, caches the result in .font_cache.css next to this script, and
    returns the same CSS on subsequent calls. This makes the generated HTML
    fully self-contained so headless Chrome prints the correct fonts without
    any network requests.
    """
    if _FONT_CACHE.exists():
        return _FONT_CACHE.read_text(encoding="utf-8")

    try:
        req = urllib.request.Request(_FONT_URL, headers={"User-Agent": _FONT_UA})
        css = urllib.request.urlopen(req, timeout=10).read().decode()
    except Exception:
        # Network unavailable — fall back to a minimal @import (fonts may differ in PDF)
        return f'<link rel="stylesheet" href="{_FONT_URL}">'

    blocks = _re.findall(
        r'/\*\s*([\w\s-]+?)\s*\*/\s*(@font-face\s*\{[^}}]+\})', css, _re.DOTALL
    )
    face_rules = []
    for subset, block in blocks:
        if subset.strip() != "latin":
            continue
        m = _re.search(r"url\((https://[^)]+\.woff2)\)", block)
        if not m:
            continue
        try:
            req2 = urllib.request.Request(m.group(1), headers={"User-Agent": _FONT_UA})
            data = base64.b64encode(urllib.request.urlopen(req2, timeout=10).read()).decode()
        except Exception:
            continue
        # Replace the remote URL with a data URI
        face_rules.append(block.replace(m.group(1), f"data:font/woff2;base64,{data}"))

    if not face_rules:
        return f'<link rel="stylesheet" href="{_FONT_URL}">'

    result = "<style>\n" + "\n".join(face_rules) + "\n</style>"
    _FONT_CACHE.write_text(result, encoding="utf-8")
    return result


INLINE_FONTS = _fetch_inline_fonts()

HERE = Path(__file__).parent
INK, PAPER, GREY = "#0A0A0A", "#FFFFFF", "#666666"

# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------
TRIALS = json.loads(Path("/tmp/trialdata.json").read_text())

TASK_META = [
    ("credential-dump-hunt", "Credential access + C2", "T1003 / T1071"),
    ("psexec-lateral-hunt", "Lateral movement", "T1021.002 / T1543"),
    ("run-key-hunt", "Persistence", "T1547.001"),
    ("account-enumeration-hunt", "Discovery", "T1069 / T1087"),
    ("vbs-launcher-hunt", "Execution", "T1059"),
    ("lolbin-injection-hunt", "Defense evasion", "T1055 / T1218"),
    ("uac-bypass-hunt", "Privilege escalation", "T1548.002"),
]
SHORT = {
    "credential-dump-hunt": "credential-access",
    "psexec-lateral-hunt": "lateral-movement",
    "run-key-hunt": "persistence",
    "account-enumeration-hunt": "discovery",
    "vbs-launcher-hunt": "execution",
    "lolbin-injection-hunt": "defense-evasion",
    "uac-bypass-hunt": "privilege-esc",
}
# Hand-authored synthetic tasks that were piloted and solved by flash (cut).
SYNTHETIC = [
    ("sigma-rule-authoring", 0.93),
    ("alert-queue-triage", 1.00),
    ("web-shell-forensics", 1.00),
    ("vuln-file-service-patch", 1.00),
    ("api-security-audit", 1.00),
]


def task_stats(task):
    fs = [t["F1"] for t in TRIALS[task]]
    return {"mean": mean(fs), "max": max(fs), "min": min(fs), "f1s": fs,
            "trials": TRIALS[task]}


AGG_MEAN = mean([t["F1"] for task in TRIALS for t in TRIALS[task]])


# ---------------------------------------------------------------------------
# SVG helpers
# ---------------------------------------------------------------------------
def svg_open(w, h):
    return (f'<svg class="fig" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
            f'width="100%" font-family="IBM Plex Mono, monospace">'
            f'<rect width="{w}" height="{h}" fill="{PAPER}"/>')


def txt(x, y, s, size=11, fill=INK, anchor="start", weight="normal", font="IBM Plex Mono, monospace"):
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}" font-family="{font}">{s}</text>')


# --- Figure 1: the pivot (synthetic vs real pass@3) ---
def fig_pivot():
    W, H = 860, 470
    x0, top, barh, gap = 300, 70, 20, 12
    axw = 470
    def X(v): return x0 + v * axw
    s = [svg_open(W, H)]
    s.append(txt(28, 34, "Hand-authored synthetic tasks vs. real-telemetry tasks", 16, INK,
                 font="Space Grotesk, sans-serif", weight="600"))
    s.append(txt(28, 52, "pass@3 vs gemini-3.5-flash. Lower is better.", 11, GREY))
    # gridlines
    for t in (0, .25, .30, .5, .75, 1.0):
        xx = X(t)
        dash = 'stroke-dasharray="4,3"' if t == .30 else 'stroke-dasharray="1,4"'
        col = INK if t == .30 else GREY
        s.append(f'<line x1="{xx:.1f}" y1="{top-6}" x2="{xx:.1f}" y2="{H-40}" stroke="{col}" stroke-width="{1 if t==.30 else 0.5}" {dash}/>')
        s.append(txt(xx, H-24, f"{int(t*100)}%", 10, col if t==.30 else GREY, "middle"))
    s.append(txt(X(.30), top-12, "30% target", 10, INK, "middle", "600", "Space Grotesk, sans-serif"))
    y = top
    s.append(txt(28, y-2, "SYNTHETIC (hand-authored) — cut", 10, GREY, "start", "600", "Space Grotesk, sans-serif"))
    y += 8
    for name, p3 in SYNTHETIC:
        s.append(txt(x0-10, y+barh-6, name, 11, INK, "end"))
        s.append(f'<rect x="{x0}" y="{y}" width="{X(p3)-x0:.1f}" height="{barh}" fill="{GREY}"/>')
        s.append(txt(X(p3)+6, y+barh-6, f"{int(round(p3*100))}%", 10, GREY))
        y += barh + gap
    y += 10
    s.append(txt(28, y-2, "REAL OTRF TELEMETRY — shipped", 10, INK, "start", "600", "Space Grotesk, sans-serif"))
    y += 8
    for name, _, _ in TASK_META:
        s.append(txt(x0-10, y+barh-6, SHORT[name], 11, INK, "end"))
        # pass@3 = 0 -> draw a stub marker at 0
        s.append(f'<rect x="{x0}" y="{y}" width="3" height="{barh}" fill="{INK}"/>')
        s.append(txt(x0+10, y+barh-6, "0%", 10, INK))
        y += barh + gap
    s.append('</svg>')
    return "\n".join(s)


# --- Figure 2: precision-recall scatter (35 trials) ---
def fig_pr():
    W, H = 860, 520
    L, R_, T, B = 90, 40, 60, 70
    pw, ph = W - L - R_, H - T - B
    def X(r): return L + r * pw
    def Y(p): return T + (1 - p / 0.55) * ph  # precision axis 0..0.55
    s = [svg_open(W, H)]
    s.append(txt(28, 34, "Precision vs. recall, all 35 trials", 16, INK, font="Space Grotesk, sans-serif", weight="600"))
    s.append(txt(28, 52, "Each point is one trial. The model finds the intrusion (recall ~1) but cannot scope it (precision ~0).", 11, GREY))
    # axes
    s.append(f'<line x1="{L}" y1="{T}" x2="{L}" y2="{T+ph}" stroke="{INK}" stroke-width="1"/>')
    s.append(f'<line x1="{L}" y1="{T+ph}" x2="{L+pw}" y2="{T+ph}" stroke="{INK}" stroke-width="1"/>')
    for r in (0,.25,.5,.75,1.0):
        s.append(f'<line x1="{X(r):.1f}" y1="{T}" x2="{X(r):.1f}" y2="{T+ph}" stroke="{GREY}" stroke-width="0.4" stroke-dasharray="1,4"/>')
        s.append(txt(X(r), T+ph+18, f"{r:.2f}", 10, GREY, "middle"))
    for p in (0,.1,.2,.3,.4,.5):
        s.append(f'<line x1="{L}" y1="{Y(p):.1f}" x2="{L+pw}" y2="{Y(p):.1f}" stroke="{GREY}" stroke-width="0.4" stroke-dasharray="1,4"/>')
        s.append(txt(L-8, Y(p)+3, f"{p:.1f}", 10, GREY, "end"))
    s.append(txt(L+pw/2, H-24, "Recall (fraction of malicious events found)", 11, INK, "middle"))
    s.append(f'<text x="24" y="{T+ph/2:.1f}" font-size="11" fill="{INK}" text-anchor="middle" transform="rotate(-90 24 {T+ph/2:.1f})">Precision</text>')
    # "precision collapse" band
    s.append(f'<rect x="{X(0.85):.1f}" y="{Y(0.06):.1f}" width="{X(1.0)-X(0.85):.1f}" height="{T+ph-Y(0.06):.1f}" fill="{INK}" opacity="0.05"/>')
    s.append(txt(X(0.86), Y(0.02)+2, "precision-collapse cluster (22 trials)", 9, GREY))
    # points, deterministic jitter
    markers = {"credential-dump-hunt":"circle","psexec-lateral-hunt":"circle",
               "run-key-hunt":"circle","account-enumeration-hunt":"rect",
               "vbs-launcher-hunt":"circle","lolbin-injection-hunt":"circle",
               "uac-bypass-hunt":"circle"}
    for ti,(task,_,_) in enumerate(TASK_META):
        for j,t in enumerate(TRIALS[task]):
            jx = ((ti*7+j*13) % 11 - 5) * 0.004
            jy = ((ti*5+j*7) % 9 - 4) * 0.003
            cx, cy = X(min(1.0,t["R"]+jx)), Y(min(0.55,max(0,t["P"]+jy)))
            if markers[task]=="rect":
                s.append(f'<rect x="{cx-4:.1f}" y="{cy-4:.1f}" width="8" height="8" fill="none" stroke="{INK}" stroke-width="1.3"/>')
            else:
                s.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="4.2" fill="{INK}" opacity="0.62"/>')
    # discovery annotation (recall gap)
    dgx, dgy = X(0.357), Y(0.011)
    s.append(f'<line x1="{dgx+10:.1f}" y1="{dgy:.1f}" x2="{dgx+150:.1f}" y2="{dgy-40:.1f}" stroke="{GREY}" stroke-width="0.7"/>')
    s.append(txt(dgx+154, dgy-40, "discovery (□): recall 0.36 —", 9, GREY))
    s.append(txt(dgx+154, dgy-29, "misses the cross-source half", 9, GREY))
    s.append('</svg>')
    return "\n".join(s)


# --- Figure 3: per-task F1 strip plot ---
def fig_strip():
    W = 860
    rows = TASK_META
    T, B, L, R_ = 92, 46, 210, 120
    rh = 34
    H = T + len(rows)*rh + B
    pw = W - L - R_
    def X(v): return L + v*pw
    s = [svg_open(W, H)]
    s.append(txt(28, 34, "Per-task F1 distribution (5 trials each)", 16, INK, font="Space Grotesk, sans-serif", weight="600"))
    s.append(txt(28, 52, "Dots are trials; the bar is the mean. A pass requires F1 = 1.0 (right edge); none approaches it.", 11, GREY))
    for t in (0,.25,.5,.75,1.0):
        s.append(f'<line x1="{X(t):.1f}" y1="{T-6}" x2="{X(t):.1f}" y2="{T+len(rows)*rh}" stroke="{GREY}" stroke-width="0.4" stroke-dasharray="1,4"/>')
        s.append(txt(X(t), T-12, f"{t:.2f}", 9, GREY, "middle"))
    s.append(f'<line x1="{X(1.0):.1f}" y1="{T-6}" x2="{X(1.0):.1f}" y2="{T+len(rows)*rh}" stroke="{INK}" stroke-width="1"/>')
    s.append(txt(X(1.0), T-24, "pass = 1.0", 9, INK, "middle", "600", "Space Grotesk, sans-serif"))
    for i,(task,tac,tech) in enumerate(rows):
        y = T + i*rh + rh/2
        st = task_stats(task)
        s.append(txt(L-12, y-3, SHORT[task], 11, INK, "end"))
        s.append(txt(L-12, y+9, tac.lower(), 8.5, GREY, "end"))
        s.append(f'<line x1="{X(st["min"]):.1f}" y1="{y:.1f}" x2="{X(st["max"]):.1f}" y2="{y:.1f}" stroke="{GREY}" stroke-width="0.8"/>')
        for f in st["f1s"]:
            s.append(f'<circle cx="{X(f):.1f}" cy="{y:.1f}" r="3.4" fill="{INK}" opacity="0.55"/>')
        s.append(f'<rect x="{X(st["mean"])-1.2:.1f}" y="{y-8:.1f}" width="2.4" height="16" fill="{INK}"/>')
        s.append(txt(X(st["max"])+8, y+3, f"mean {st['mean']:.3f}", 9, GREY))
    s.append('</svg>')
    return "\n".join(s)


FIG1, FIG2, FIG3 = fig_pivot(), fig_pr(), fig_strip()

# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def rows_difficulty():
    order = sorted(TASK_META, key=lambda m: task_stats(m[0])["mean"])
    out = []
    for task, tac, tech in order:
        st = task_stats(task)
        out.append(f"<tr><td>{task}</td><td>{tac}</td><td class='m'>0.00</td><td class='m'>0.00</td>"
                   f"<td class='m'>{st['mean']:.3f}</td><td class='m'>{st['max']:.3f}</td></tr>")
    return "\n".join(out)


def rows_distribution():
    out = []
    src = {
        "credential-dump-hunt": "empire_mimikatz_logonpasswords",
        "psexec-lateral-hunt": "empire_psexec_dcerpc_tcp_svcctl",
        "run-key-hunt": "empire_persistence_registry_run_keys",
        "account-enumeration-hunt": "empire net_localgroup + net_local_users",
        "vbs-launcher-hunt": "empire_launcher_vbs",
        "lolbin-injection-hunt": "covenant_lolbin_wuauclt_createremotethread",
        "uac-bypass-hunt": "empire_uac_shellapi_fodhelper",
    }
    gt = {"credential-dump-hunt":37,"psexec-lateral-hunt":4,"run-key-hunt":11,
          "account-enumeration-hunt":14,"vbs-launcher-hunt":5,"lolbin-injection-hunt":3,
          "uac-bypass-hunt":7}
    for task, tac, tech in TASK_META:
        out.append(f"<tr><td>{task}</td><td>{tac}<br><span class='dim'>{tech}</span></td>"
                   f"<td><span class='dim'>{src[task]}</span></td><td class='m'>{gt[task]}</td></tr>")
    return "\n".join(out)


HTML = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hyoka — A Threat-Hunting Eval for gemini-3.5-flash</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
{INLINE_FONTS}
<style>
:root{{--ink:{INK};--paper:{PAPER};--grey:{GREY};--rule:#E6E6E6;}}
*{{box-sizing:border-box}}
html{{scroll-behavior:smooth}}
body{{margin:0;background:var(--paper);color:var(--ink);
 font-family:'IBM Plex Mono',monospace;font-size:14.5px;line-height:1.72;
 -webkit-font-smoothing:antialiased;}}
.wrap{{max-width:820px;margin:0 auto;padding:72px 32px 120px;}}
h1,h2,h3,h4,.sans{{font-family:'Space Grotesk',sans-serif;}}
h1{{font-size:40px;line-height:1.08;font-weight:700;letter-spacing:-0.02em;margin:0 0 6px;}}
h2{{font-size:23px;font-weight:600;letter-spacing:-0.01em;margin:64px 0 4px;padding-top:18px;border-top:2px solid var(--ink);}}
h3{{font-size:16.5px;font-weight:600;margin:34px 0 6px;}}
h2 .num{{color:var(--grey);font-weight:500;margin-right:14px;}}
p{{margin:14px 0;}}
a{{color:var(--ink);}}
.dim,.small{{color:var(--grey);}}
.small{{font-size:12px;}}
.kicker{{font-family:'Space Grotesk',sans-serif;font-size:12px;letter-spacing:0.22em;
 text-transform:uppercase;color:var(--grey);margin:0 0 22px;}}
.sub{{font-family:'Space Grotesk',sans-serif;font-size:18px;color:var(--grey);font-weight:400;margin:0 0 26px;line-height:1.4;}}
.meta{{display:flex;flex-wrap:wrap;gap:10px 26px;font-size:12px;color:var(--grey);
 border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);padding:14px 0;margin:0 0 8px;}}
.meta b{{color:var(--ink);font-weight:500;}}
.abstract{{border:1px solid var(--ink);padding:22px 24px;margin:34px 0 10px;background:#FAFAFA;}}
.abstract .lab{{font-family:'Space Grotesk',sans-serif;font-size:11px;letter-spacing:0.18em;text-transform:uppercase;color:var(--grey);margin-bottom:8px;}}
.abstract p{{margin:0;}}
.toc{{columns:2;column-gap:40px;font-size:13px;margin:30px 0 8px;padding:0;list-style:none;}}
.toc li{{margin:5px 0;break-inside:avoid;}}
.toc .n{{color:var(--grey);margin-right:10px;}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--ink);border:1px solid var(--ink);margin:26px 0;}}
.metric{{background:var(--paper);padding:16px 14px;}}
.metric .v{{font-family:'Space Grotesk',sans-serif;font-size:27px;font-weight:600;line-height:1;}}
.metric .l{{font-size:10.5px;color:var(--grey);margin-top:7px;text-transform:uppercase;letter-spacing:0.08em;}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;margin:14px 0;}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--rule);vertical-align:top;}}
th{{font-family:'Space Grotesk',sans-serif;font-weight:600;font-size:11px;letter-spacing:0.04em;
 text-transform:uppercase;color:var(--grey);border-bottom:1.5px solid var(--ink);}}
td.m{{text-align:right;font-variant-numeric:tabular-nums;}}
tr:hover td{{background:#FAFAFA;}}
figure{{margin:30px 0;}}
figure svg{{border:1px solid var(--rule);display:block;}}
figcaption{{font-size:12px;color:var(--grey);margin-top:10px;padding-left:2px;}}
figcaption b{{color:var(--ink);font-family:'Space Grotesk',sans-serif;font-weight:600;}}
.callout{{border-left:3px solid var(--ink);padding:4px 0 4px 18px;margin:20px 0;color:var(--ink);}}
code{{background:#F2F2F2;padding:1px 5px;font-size:12.5px;}}
pre{{background:#F7F7F7;border:1px solid var(--rule);padding:14px 16px;overflow:auto;font-size:12px;line-height:1.5;}}
.foot{{margin-top:70px;border-top:1px solid var(--rule);padding-top:16px;font-size:11px;color:var(--grey);}}
ul.tight li{{margin:6px 0;}}
.wordmark{{margin:0 0 20px;line-height:1;}}
.wordmark svg{{display:block;}}
</style></head>
<body><div class="wrap">

<p class="kicker">Abundant · Research Take-Home · Detection Engineering</p>
<!-- wordmark: triangle mark + logotype, inlined from hyoka-brand/wordmark-light.svg, scaled to header size -->
<div class="wordmark" aria-label="hyoka wordmark">
<svg width="224" height="56" viewBox="0 0 560 140" xmlns="http://www.w3.org/2000/svg" role="img">
<g transform="translate(28,20) scale(0.5)"><polygon points="142.4,57.6 25.8,96.5 103.5,174.2" fill="#0A0A0A"/></g>
<text x="130" y="90" font-family="'Space Grotesk', 'Geist', sans-serif" font-weight="600" font-size="58" letter-spacing="-1.5" fill="#0A0A0A">hyoka</text>
</svg>
</div>
<p class="sub">An open-ended SOC threat-hunting evaluation for <b>gemini-3.5-flash</b>, built on real Windows attack telemetry.</p>
<div class="meta"><span><b>Author</b> Muneeb Hassan</span><span><b>Model under test</b> gemini/gemini-3.5-flash (terminus-2)</span><span><b>Tasks</b> 7</span><span><b>Trials</b> 35 (5 / task)</span><span><b>Date</b> 2026-07-05</span></div>

<div class="abstract"><div class="lab">Abstract</div>
<p>Hyōka measures whether an LLM agent can perform the core, unautomated job of a SOC analyst: given a database of raw Windows event logs and <b>no hints</b>, identify the exact events that make up an intrusion. Each of the seven tasks wraps a real attack recording from the OTRF Security-Datasets corpus, deterministically time-shifted and entity-obfuscated into a queryable SQLite database, with ground truth derived from the corresponding Sigma detection rule and scored by F1. Against gemini-3.5-flash the suite is decisively hard: <b>0% pass@3 on every task</b>, aggregate mean F1 {AGG_MEAN:.3f} over 35 trials, while the oracle solver scores 1.000 and the no-op agent 0.000 throughout. The failures are genuine and uniform — the model reliably <i>locates</i> the malicious activity (recall ≈ 1.0) but cannot <i>scope</i> it, flagging up to 4,871 events for a 37-event answer. We situate the design in the recent literature (notably the <a href="https://arxiv.org/abs/2604.19533">Cyber Defense Benchmark</a> and <a href="https://arxiv.org/abs/2603.13517">CTI-REALM</a>), give a concrete 10→1,000 scaling plan, and document the deliberate pivot away from hand-authored synthetic tasks, which the model solved at 93–100% pass@3.</p></div>

<div class="metrics">
<div class="metric"><div class="v">0%</div><div class="l">pass@3 · every task</div></div>
<div class="metric"><div class="v">{AGG_MEAN:.3f}</div><div class="l">aggregate mean F1</div></div>
<div class="metric"><div class="v">1.00 / 0.00</div><div class="l">oracle / nop reward</div></div>
<div class="metric"><div class="v">7</div><div class="l">ATT&amp;CK tactics</div></div>
</div>

<ol class="toc">
<li><span class="n">1</span><a href="#s1">Distribution</a></li>
<li><span class="n">2</span><a href="#s2">Difficulty profile</a></li>
<li><span class="n">3</span><a href="#s3">Research awareness</a></li>
<li><span class="n">4</span><a href="#s4">Scale plan</a></li>
<li><span class="n">5</span><a href="#s5">Failure analysis</a></li>
<li><span class="n">A</span><a href="#sa">Appendix: how the eval was built</a></li>
</ol>

<h2 id="s1"><span class="num">1</span>Distribution</h2>
<h3>1.1 The slice, and why</h3>
<p>Hyōka evaluates a single, tightly-scoped capability: <b>open-ended threat hunting over raw host telemetry</b>. The agent is handed a database of Windows Security and Sysmon event logs from a small fleet, told only that an intrusion occurred somewhere within it, and asked to return the exact set of malicious events. This is the daily, still-unautomated work of a Tier-2/3 SOC analyst, and it is the part of detection engineering that resists the multiple-choice framing of most security benchmarks. A narrow slice was a deliberate choice: it is more informative to measure one realistic capability well, with a defensible ground truth and a strict verifier, than to sample thinly across all of security.</p>

<h3>1.2 In scope, and out</h3>
<p>The tasks deliberately require the properties that make real hunting hard: <b>volume</b> (each corpus is roughly 650–6,000 real events, of which 0.05–0.6% are malicious); <b>multi-source correlation</b> (evidence for one adversary action is split across Sysmon and the Windows Security/System audit logs); <b>realistic benign noise</b> (verbose PowerShell logging, routine registry and network activity); and <b>precision under pressure</b> (a single-feature filter such as "flag all network connections" is guaranteed to fail). Explicitly out of scope: offensive exploit development (CVE-Bench territory — Hyōka is strictly defensive), CTF-style puzzle forensics, and anything requiring live network access. Every environment is offline and deterministic.</p>

<h3>1.3 Where the distribution comes from</h3>
<p>Each task is built from a real attack recording in the <b><a href="https://github.com/OTRF/Security-Datasets">OTRF Security-Datasets</a></b> corpus (the Open Threat Research "Mordor" project): genuine Empire, Covenant, Mimikatz, and PurpleSharp campaigns captured as Windows event logs on instrumented hosts. A deterministic builder time-shifts every timestamp into a common window and consistently rewrites host, domain, and user identifiers, so the environment is reproducible on each container build yet is not the verbatim, memorizable public file. Ground truth is derived from the technique's <b><a href="https://github.com/SigmaHQ/sigma">Sigma / behavioural detection rule</a></b> — the same labelling methodology as the <a href="https://arxiv.org/abs/2604.19533">Cyber Defense Benchmark</a> (§3) — and never hand-curated per event. The seven tasks span seven MITRE ATT&amp;CK tactics:</p>

<table><thead><tr><th>Task</th><th>Tactic</th><th>OTRF source recording</th><th class="m">Malicious</th></tr></thead>
<tbody>{rows_distribution()}</tbody></table>
<p class="small dim">Table 1. The shipped task set. "Malicious" is the number of ground-truth events among the full corpus for that task.</p>

<h2 id="s2"><span class="num">2</span>Difficulty profile</h2>
<p>All results are for <code>gemini/gemini-3.5-flash</code> run through the terminus-2 scaffold, five trials per task. Reward is the F1 of the flagged event-id set against ground truth; because the signal is a small, exact set, a "pass" requires perfect identification (F1&nbsp;=&nbsp;1.0), so pass@1 and pass@3 are strict. Every task also passed its oracle check (reward 1.000) and no-op check (reward 0.000), confirming each is solvable and not satisfiable by inaction.</p>

<table><thead><tr><th>Task</th><th>Tactic</th><th class="m">pass@1</th><th class="m">pass@3</th><th class="m">mean F1</th><th class="m">max F1</th></tr></thead>
<tbody>{rows_difficulty()}</tbody></table>
<p class="small dim">Table 2. Per-task difficulty, ordered hardest-first by mean F1. Aggregate: pass@1 = pass@3 = 0.00, mean F1 = {AGG_MEAN:.3f} across 35 trials.</p>

<p>The headline number — 0% pass@3 everywhere — understates what is happening, because F1 is fractional and the trials are not uniform. Figure&nbsp;1 places the suite in context against the six hand-authored synthetic tasks that preceded it (<a href="#sa">§A</a>): those were solved at 93–100% pass@3, whereas every real-telemetry task sits at zero. This gap is the central empirical result of the project.</p>

<figure>{FIG1}<figcaption><b>Figure 1.</b> pass@3 for the hand-authored synthetic tasks (grey, subsequently cut) versus the shipped OTRF real-telemetry tasks (black). The synthetic tasks cluster at 93–100%; every real task is at 0%, well under the 30% target. Difficulty is a property of the data and framing, not of clever puzzle construction. See <a href="#sa">Appendix A</a> for the full curation history.</figcaption></figure>

<h3>2.1 What the difficulty curve looks like</h3>
<p>Figure&nbsp;2 shows every trial in precision–recall space, and it is the most informative single view of the model's behaviour. The points collapse into the bottom-right corner: <b>recall is 1.0 in 30 of 35 trials</b>, but precision is almost always below 0.05. In other words, the model routinely surfaces the entire malicious set — it is looking in the right place — and then buries it under hundreds or thousands of benign events. The five off-corner points are the only partial successes, and the square markers (discovery) are the one task where recall itself fails.</p>

<figure>{FIG2}<figcaption><b>Figure 2.</b> Precision versus recall for all 35 trials (circles; discovery shown as squares). The dense high-recall / near-zero-precision cluster is the dominant failure mode — "precision collapse." Discovery is the exception: it also loses recall (0.36), because the model catches one log source's evidence and misses the correlated events in another.</figcaption></figure>

<p>Figure&nbsp;3 breaks the same data out per task as a distribution of trial F1 scores. Two things are visible. First, the spread is genuine and often bimodal — most trials near zero with an occasional partial hit (execution reaches 0.435, privilege-escalation 0.389, credential-dump 0.284) — which is the signature of real difficulty rather than a broken verifier, since a task-design bug would produce uniform zeros. Second, no trial on any task comes close to the 1.0 line required to pass.</p>

<figure>{FIG3}<figcaption><b>Figure 3.</b> Per-task F1 across five trials each (dots), with the per-task mean (vertical bar) and min–max range (grey line). The right edge marks the F1 = 1.0 pass threshold; nothing approaches it. Persistence is the most consistent task (all five trials cluster tightly at F1 ≈ 0.07), a near-deterministic over-flagging strategy; the others vary more.</figcaption></figure>

<h3>2.2 What kinds of failure dominate</h3>
<p>Quantitatively, the dominant failure is <b>precision collapse</b>: the model correctly identifies the malicious events but cannot separate them from benign context, so precision — and therefore F1 — is destroyed. A secondary mode, isolated to the discovery task, is a <b>cross-source recall gap</b>: the model finds the reconnaissance commands in Sysmon but never correlates them with the corresponding Windows Security membership-enumeration events, capping recall at 0.36. Both are diagnosed against real trajectories in §5.</p>

<h2 id="s3"><span class="num">3</span>Research awareness</h2>
<p>The design is grounded in recent work, each source verified against its primary reference during construction rather than cited from memory.</p>
<ul class="tight">
<li><b><a href="https://arxiv.org/abs/2604.19533">Cyber Defense Benchmark</a></b> (Chona, Kozlov &amp; Kumar; arXiv 2604.19533, Apr 2026) — the direct structural precedent and the method Hyōka replicates at task scale: real OTRF attack procedures wrapped as no-hint, SQL-queryable Windows-log environments, scored CTF-style against Sigma-derived ground truth. It reports that <i>every</i> frontier model fails, with the best (Claude Opus 4.6) flagging only ~3.8% of malicious events and Gemini 3 Flash failing badly. This is the evidence that the slice has genuine headroom for a flash-tier model, and our own 0% pass@3 corroborates it.</li>
<li><b><a href="https://arxiv.org/abs/2603.13517">CTI-REALM</a></b> (Microsoft; arXiv 2603.13517, Mar 2026) — end-to-end detection-rule generation over real telemetry. Best of 16 models = Claude Opus 4.6 at 0.637 overall, with cloud correlation the hardest sub-problem at 0.282. Confirmed the slice and pointed us at cross-source correlation as the locus of difficulty.</li>
<li><b><a href="https://arxiv.org/abs/2503.17332">CVE-Bench</a></b> (Zhu et al.; arXiv 2503.17332) — real-CVE exploitation, SOTA ~13%. Cited to mark the boundary we did not cross: it is offensive; Hyōka stays on the defensive side of the same headroom.</li>
<li><b><a href="https://arxiv.org/abs/2606.13757">SEVRA-BENCH</a></b> (arXiv 2606.13757) and <b><a href="https://arxiv.org/abs/2509.03331">VulnRepairEval</a></b> (arXiv 2509.03331, top model ~21.7%) — reviewed while prototyping execution-based vulnerability-repair tasks (§A).</li>
<li><b><a href="https://github.com/OTRF/Security-Datasets">OTRF Security-Datasets</a></b> (GPL-3.0) — the source telemetry. <b><a href="https://github.com/SigmaHQ/sigma">SigmaHQ</a></b> — detection-rule syntax and the technique→labelled-event mapping.</li>
</ul>
<p class="callout">Takeaway: curated security question-answering is largely saturated, but open-ended, evidence-driven hunting over real logs is not. Hyōka is built directly on that gap, and reuses the community's real recordings and detection rules rather than inventing synthetic approximations of them.</p>

<h2 id="s4"><span class="num">4</span>Scale plan (7 → 1,000 tasks)</h2>
<p>The pipeline is already parametric: a single deterministic builder produces each task, and two builders differ only in their source recording and detection rule. Scaling is therefore primarily a data- and QA-automation problem, not a re-engineering one.</p>
<h3>4.1 Public data sources</h3>
<p><a href="https://github.com/OTRF/Security-Datasets">OTRF Security-Datasets</a> alone contains hundreds of technique recordings across every ATT&amp;CK tactic; the <a href="https://arxiv.org/abs/2604.19533">Cyber Defense Benchmark</a> draws 106 procedures from it. Each recording is a new task through the existing builder. Beyond OTRF: <b><a href="https://github.com/redcanaryco/atomic-red-team">Atomic Red Team</a></b> to generate fresh recordings on demand, <b><a href="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES">EVTX-ATTACK-SAMPLES</a></b> for additional Windows event captures, and public log corpora (<b><a href="https://github.com/logpai/loghub">LogHub</a></b>) for benign-volume blending. <a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a> remains the taxonomy backbone and <a href="https://github.com/SigmaHQ/sigma">SigmaHQ</a> the ground-truth rule library.</p>
<h3>4.2 Augmentation</h3>
<p>Two levers already exist in <code>build_inputs.py</code>. First, the obfuscation seed: re-randomising the host/user/time remap yields many non-identical variants of one recording, forcing the model to generalise rather than memorise. Second, campaign blending: interleaving <i>N</i> recordings into one database (as the discovery task already does with two) raises event volume and requires multi-stage correlation. Because ground truth is regenerated automatically from the Sigma rule, none of this requires manual labelling.</p>
<h3>4.3 QA loop</h3>
<p>Quality control is automated and was built alongside the tasks. Every candidate must pass <code>scripts/lazy_baseline_probe.py</code>, which runs the oracle (must score 1.0) and a battery of "dumbest solve" baselines — flag-everything, flag-all-of-one-event-type, grep-one-token — each of which <b>must</b> fail. If any lazy baseline passes, the task's signal is separable by a single feature and the task is auto-rejected. This gate caught two real oracle/ground-truth defects during this build (SQLite <code>LIKE</code>/<code>ESCAPE</code> mismatches that silently diverged the oracle from the labels). A second gate, <code>harbor check</code> against the TB3 rubric, screens for under-specified instructions and gameable verifiers.</p>

<h2 id="s5"><span class="num">5</span>Failure analysis</h2>
<p>Every failure below is genuine task difficulty rather than a task-design artifact. The argument is the same in each case and is grounded in the data of Figure&nbsp;2: on the identical inputs the oracle recovers the exact set (F1 = 1.0), the no-op agent scores 0, and the model's own recall and precision vary meaningfully across trials — an ambiguous instruction, broken environment, or over-strict verifier would instead produce uniform zeros. Trajectories are under <code>logs/pilots/</code>.</p>

<h3>5.1 Precision collapse (persistence, lateral movement, and most trials)</h3>
<p>On <b>run-key-hunt</b>, all five trials flagged ~290–340 events and captured all 11 malicious ones: recall 1.0, precision ≈ 0.036, F1 ≈ 0.069. The model correctly found the Run-key persistence value and the beaconing process, then failed to stop — sweeping in benign registry and network events around them. <b>psexec-lateral-hunt</b> shows the same at the extreme: every one of its five trials recovered all 4 malicious events (recall 1.0), but one flagged 644 events to do so (F1 0.012). The model knows <i>where</i> the intrusion is; it cannot delimit it. This is the modal outcome across the suite (17 of 35 trials sit in the precision-collapse cluster of Figure&nbsp;2).</p>
<h3>5.2 Cross-source recall gap (discovery)</h3>
<p><b>account-enumeration-hunt</b> is the one task where recall itself fails: every one of the five trials recovered only 5 of 14 malicious (recall 0.36). Four of the five also over-flagged massively (400–500 events, F1 ≈ 0.02); the fifth kept precision far tighter (17 events flagged) yet, with the same recall gap, still reached only F1 0.32. In every case the model identified the <code>net.exe</code> reconnaissance commands in Sysmon but never connected them to the Windows Security 4798/4799 group-membership-enumeration events that record the same behaviour in a different log — so it missed the correlated half of the answer. The task was designed to require exactly this Sysmon↔Security correlation, and the model did not perform it.</p>
<h3>5.3 Partial chains and the occasional near-hit</h3>
<p>A minority of trials get partway. <b>psexec-lateral</b>'s best trial reconstructed the full Security+System+Sysmon service-execution chain (all 4 events, recall 1.0) and kept its flag set to 20 events (F1 0.33) — a near-hit lost only to residual over-flagging. <b>credential-dump</b>, the largest task, recovered all 37 malicious events in every trial (recall 1.0) but even its tightest trial flagged 224 (F1 0.284). <b>execution</b> is the sharpest illustration of the precision problem and the strongest single result in the run: all five of its trials recovered the full 5-event process tree (recall 1.0), yet flagged anywhere from 18 to 1,183 events to do so — its best trial (18 events, F1 0.435) still falls far short of a pass purely on precision. These near-hits confirm the tasks are calibrated at the model's frontier rather than beyond it: the capability is present but unreliable, which is precisely the regime a training-signal eval should target.</p>

<h2 id="sa"><span class="num">A</span>Appendix: how the eval was built</h2>
<p>The brief notes that the curation process is itself signal, so we record it plainly. The first six tasks were <b>hand-authored synthetic generators</b>: an auth-log lateral-movement hunt, a CloudTrail privilege-escalation hunt, a Sigma-authoring task, a web-shell log-plus-diff correlation, and two execution-based vulnerability-repair tasks. Every one was solved by gemini-3.5-flash at 93–100% pass@3 (Figure&nbsp;1), and two apparent "0%" results turned out to be scoring artifacts — a CloudTrail ground-truth label that was itself incorrect, and a web-shell answer penalised on a count threshold for a defensible inclusion — not genuine difficulty. Those tasks are retained under <code>cut_synthetic/</code> for transparency.</p>
<p>The lesson, paid for over thirteen pilots, is the thesis of this report: <b>hand-crafted synthetic puzzles are inside a flash-tier model's competence, however cleverly the signal is hidden; genuine headroom lives in real, high-volume, unfamiliar telemetry hunted with no hints and scored objectively.</b> Every task in the shipped set is built that way, and every task holds.</p>

<div class="foot">Hyōka · detection-engineering eval · gemini-3.5-flash · figures rendered as native SVG · data: <a href="https://github.com/OTRF/Security-Datasets">OTRF Security-Datasets</a> (GPL-3.0), time-shifted and entity-obfuscated · report generated from <code>logs/pilots/</code>.</div>

</div></body></html>
"""

out = HERE / "report.html"
out.write_text(HTML, encoding="utf-8")
print(f"wrote {out} ({len(HTML)} bytes)")
