"""
Held-out labeled evaluation corpus and a genuine (minimal) Sigma rule evaluator
for the sigma-rule-authoring-c2-beacon task.

This module is part of ``tests/`` and is only present during the verification
phase -- the agent never sees it or the labeled rows it generates at task time.
The reward is the F1 score of the agent's rule against this corpus.

The evaluator is a real, generalizable Sigma matcher (not a hardcoded answer
check): it compiles the rule's ``detection`` selections and boolean
``condition`` and applies them row-by-row. It supports scalar and list values,
the ``contains`` / ``startswith`` / ``endswith`` / ``re`` field modifiers,
bare keyword lists, and ``and`` / ``or`` / ``not`` / parenthesised conditions
plus ``all of them`` / ``1 of them``.
"""
from __future__ import annotations

import random
import re

import yaml

# Beacon fingerprint -- the behavioral fields (User-Agent, URI structure, response
# size) match the agent-facing proxy_logs.csv, but the beacon here rides a DIFFERENT
# C2 domain that never appears in the agent's data. A rule keyed on the domain the
# agent saw therefore cannot match anything in this corpus; only a domain-free
# behavioral rule generalizes. (Domain/IP references are additionally rejected --
# see ``references_domain_or_ip``.)
BEACON_HOST = "ws-finance-04"
BEACON_DOMAIN = "cdn-assets-eu.fastlyr.net"
HELDOUT_BEACON_DOMAIN = "c2-beacon-delta.nexuscdn-eu.com"
BEACON_UA = "Mozilla/5.0 (compatible; SyncAgent/1.0)"
BOOTSTRAP_DOMAIN = "cdn-assets-eu.bootstrapcdn.com"
HR_DECOY_DOMAIN = "cdn-eu-assets.cloudfrontcdn.net"
SCHED_DECOY_DOMAIN = "telemetry-sync.azureedge-cdn.net"

UA_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
UA_FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0"
UA_TEAMS = "Microsoft Teams/1.6.00.4472 (Windows NT 10.0; Win64; x64)"
UA_UPDATER = "Microsoft-Delivery-Optimization/10.0"
BROWSER_UAS = [UA_CHROME, UA_FIREFOX]

ACK_DOMAINS = ["analytics.example-corp.com", "ping.telemetry-svc.net", "metrics.saas-vendor.io"]
ACK_PATHS = ["/collect", "/beacon", "/p"]
UPDATE_ENDPOINTS = [("updates.vendor-portal.com", "/client/v3/update"),
                    ("patch-mgmt.internal-tools.net", "/agent/update")]
ACK_HOSTS = ["ws-finance-04", "ws-dev-12", "ws-hr-07"]

FIELDNAMES = ["timestamp", "src_host", "dst_domain", "uri_path",
              "user_agent", "http_method", "response_code", "response_bytes"]

# Held-out row counts. The rule is graded on domain-free behavioral fields only
# (any dst_domain / IP reference is rejected outright -- see references_domain_or_ip),
# and the beacon rides a domain absent from the agent's data. With 200 beacon
# positives and recall pinned at 1.0, a single behavioral field's F1 is 200/(200+FP)
# turned into F1 = 2*p/(1+p); FP must exceed ~71 to fall below 0.85:
#   uri /v2/ prefix alone   -> beacon+bootstrap        FP=150 -> F1 ~ 0.727
#   User-Agent alone        -> beacon+hr_burst+sched   FP=200 -> F1 ~ 0.667
#   response_bytes==16 alone-> beacon+ack_204          FP=100 -> F1 ~ 0.800
#   uri endswith /update    -> beacon+update_noise     FP=100 -> F1 ~ 0.800
# Only combining >=2 behavioral fields (UA + URI regex + response size) reaches 1.0.
# The benign_fastlyr set (domain-only decoy) is retained as realistic noise even
# though domain rules are now rejected.
N_BEACON = 200
N_BOOTSTRAP = 150
N_HR_BURST = 100
N_SCHED_DECOY = 100
N_BENIGN_FASTLYR = 80
N_ACK_16B = 100
N_UPDATE_NOISE = 100
N_BROWSING = 470


def _row(src, dom, uri, ua, method, code, nbytes) -> dict:
    """Assemble one labeled-corpus row (timestamp is not needed for evaluation)."""
    return {
        "timestamp": "2026-06-12T00:00:00Z",
        "src_host": src,
        "dst_domain": dom,
        "uri_path": uri,
        "user_agent": ua,
        "http_method": method,
        "response_code": code,
        "response_bytes": nbytes,
    }


def build_holdout_corpus() -> list[tuple[dict, int]]:
    """Return the deterministic list of (row, label) pairs; label 1 == beacon."""
    rng = random.Random(72026)
    corpus: list[tuple[dict, int]] = []

    for _ in range(N_BEACON):
        hexp = f"{rng.randrange(16 ** 8):08x}"
        corpus.append((_row(BEACON_HOST, HELDOUT_BEACON_DOMAIN, f"/v2/{hexp}/update",
                             BEACON_UA, "GET", 200, 16), 1))

    for _ in range(N_BOOTSTRAP):
        ver = rng.choice(["3.4.1", "4.6.2", "5.2.0"])
        corpus.append((_row(rng.choice(["ws-dev-12", "ws-hr-07"]), BOOTSTRAP_DOMAIN,
                             f"/v2/{ver}/bundle.js", rng.choice(BROWSER_UAS),
                             "GET", 200, rng.randint(41000, 96000)), 0))

    for i in range(N_HR_BURST):
        corpus.append((_row("ws-hr-07", HR_DECOY_DOMAIN, f"/download/pkg_{i:03d}.bin",
                             BEACON_UA, "GET", 200, rng.randint(210000, 900000)), 0))

    for _ in range(N_SCHED_DECOY):
        hexp = f"{rng.randrange(16 ** 8):08x}"
        corpus.append((_row("ws-dev-12", SCHED_DECOY_DOMAIN, f"/telemetry/{hexp}/report",
                             BEACON_UA, "GET", 200, rng.randint(128, 4096)), 0))

    for _ in range(N_BENIGN_FASTLYR):
        path = rng.choice(["/assets/img/logo.png", "/css/main.min.css", "/js/app.min.js"])
        corpus.append((_row(rng.choice(["ws-dev-12", "ws-finance-04"]), BEACON_DOMAIN,
                             path, rng.choice(BROWSER_UAS), "GET",
                             rng.choice([200, 304]), rng.randint(1800, 130000)), 0))

    for _ in range(N_ACK_16B):
        corpus.append((_row(rng.choice(ACK_HOSTS), rng.choice(ACK_DOMAINS),
                             rng.choice(ACK_PATHS), rng.choice(BROWSER_UAS),
                             "GET", 204, 16), 0))

    for _ in range(N_UPDATE_NOISE):
        dom, path = rng.choice(UPDATE_ENDPOINTS)
        corpus.append((_row(rng.choice(ACK_HOSTS), dom, path,
                             rng.choice(BROWSER_UAS + [UA_UPDATER]),
                             "GET", 200, rng.randint(1024, 65536)), 0))

    for _ in range(N_BROWSING):
        dom = rng.choice(["www.google.com", "github.com", "teams.microsoft.com",
                          "cdn.jsdelivr.net", "outlook.office365.com"])
        ua = UA_TEAMS if dom == "teams.microsoft.com" else rng.choice(BROWSER_UAS)
        corpus.append((_row(rng.choice(["ws-dev-12", "ws-hr-07", "ws-finance-04"]), dom,
                             rng.choice(["/", "/api/v1/presence", "/static/app.js", "/favicon.ico"]),
                             ua, rng.choice(["GET", "POST"]),
                             rng.choice([200, 304]), rng.randint(200, 320000)), 0))

    return corpus


def _match_field(row: dict, field_spec: str, expected) -> bool:
    """Evaluate a single ``field[|modifier]: value`` clause against a row."""
    parts = field_spec.split("|")
    field = parts[0]
    modifier = parts[1] if len(parts) > 1 else None

    if field not in row:
        return False
    actual = str(row[field])
    candidates = expected if isinstance(expected, list) else [expected]

    for exp in candidates:
        exp_s = str(exp)
        if modifier is None:
            if actual == exp_s:
                return True
        elif modifier == "contains":
            if exp_s.lower() in actual.lower():
                return True
        elif modifier == "startswith":
            if actual.lower().startswith(exp_s.lower()):
                return True
        elif modifier == "endswith":
            if actual.lower().endswith(exp_s.lower()):
                return True
        elif modifier == "re":
            try:
                if re.search(exp_s, actual):
                    return True
            except re.error:
                return False
        else:
            if actual == exp_s:
                return True
    return False


def _match_selection(row: dict, selection) -> bool:
    """Evaluate one named selection block against a row."""
    if isinstance(selection, dict):
        return all(_match_field(row, fspec, exp) for fspec, exp in selection.items())
    haystack = " ".join(str(v) for v in row.values()).lower()
    if isinstance(selection, list):
        return any(str(kw).lower() in haystack for kw in selection)
    return str(selection).lower() in haystack


def _eval_condition(condition: str, results: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition expression over pre-computed selection results."""
    names = list(results.keys())
    if not condition:
        expr = " and ".join(names) if names else "False"
    else:
        expr = condition.strip()
        expr = re.sub(r"\ball\s+of\s+them\b", "(" + " and ".join(names) + ")" if names else "False", expr)
        expr = re.sub(r"\b1\s+of\s+them\b", "(" + " or ".join(names) + ")" if names else "False", expr)
        expr = re.sub(r"\bany\s+of\s+them\b", "(" + " or ".join(names) + ")" if names else "False", expr)

    def repl(match: re.Match) -> str:
        word = match.group(0)
        if word in ("and", "or", "not", "True", "False"):
            return word
        if word in results:
            return "True" if results[word] else "False"
        return "False"

    py_expr = re.sub(r"[A-Za-z_][A-Za-z0-9_]*", repl, expr)
    if not re.fullmatch(r"[\s()TrueFalsandot]*", py_expr):
        return False
    try:
        return bool(eval(py_expr, {"__builtins__": {}}, {}))
    except Exception:
        return False


def load_rule(text: str) -> dict:
    """Parse rule YAML text and validate the minimum required structure."""
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("rule is not a YAML mapping")
    detection = data.get("detection")
    if not isinstance(detection, dict) or not detection:
        raise ValueError("rule has no usable 'detection' block")
    return data


IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
DOMAIN_FIELDS = {"dst_domain", "dest_domain", "domain", "dst_ip", "dest_ip", "ip", "src_ip"}


def _iter_values(obj):
    """Yield every scalar value nested within a dict/list structure."""
    if isinstance(obj, dict):
        for value in obj.values():
            yield from _iter_values(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _iter_values(value)
    else:
        yield obj


def references_domain_or_ip(rule: dict) -> tuple[bool, str]:
    """Return (True, reason) if the rule references a specific domain field or IP literal.

    The task requires rules to generalize across C2 domains, so a rule may not key
    on a destination domain field or embed an IP address. Such rules are scored 0.0.
    """
    detection = rule.get("detection", {})
    if isinstance(detection, dict):
        for name, selection in detection.items():
            if name == "condition" or not isinstance(selection, dict):
                continue
            for field_spec in selection.keys():
                base_field = str(field_spec).split("|")[0].strip().lower()
                if base_field in DOMAIN_FIELDS:
                    return True, f"rule references a destination field '{field_spec}'"
    for value in _iter_values(detection):
        if isinstance(value, str) and IP_RE.search(value):
            return True, f"rule references an IP address literal: {value!r}"
    return False, ""


def rule_predicts(rule: dict, row: dict) -> bool:
    """Return True if the compiled rule fires on the given row."""
    detection = rule["detection"]
    condition = detection.get("condition")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        return False
    results = {name: _match_selection(row, sel) for name, sel in selections.items()}
    return _eval_condition(condition, results)


def score_rule(rule: dict, corpus: list[tuple[dict, int]]) -> dict:
    """Evaluate a parsed rule against the labeled corpus and return F1 metrics."""
    tp = fp = fn = 0
    for row, label in corpus:
        predicted = rule_predicts(rule, row)
        if predicted and label:
            tp += 1
        elif predicted and not label:
            fp += 1
        elif not predicted and label:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"f1": f1, "precision": precision, "recall": recall,
            "tp": tp, "fp": fp, "fn": fn}


def f1_for_rule_text(text: str) -> dict:
    """Parse rule text and score it, returning zeroed metrics on any parse failure."""
    try:
        rule = load_rule(text)
    except Exception as exc:
        return {"f1": 0.0, "precision": 0.0, "recall": 0.0,
                "tp": 0, "fp": 0, "fn": 0, "error": str(exc)}
    referenced, reason = references_domain_or_ip(rule)
    if referenced:
        return {"f1": 0.0, "precision": 0.0, "recall": 0.0,
                "tp": 0, "fp": 0, "fn": 0, "error": reason}
    return score_rule(rule, build_holdout_corpus())
