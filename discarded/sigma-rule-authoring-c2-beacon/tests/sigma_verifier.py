"""
Verifier core for sigma-rule-authoring-c2-beacon.

Provides a compact Sigma-rule matcher, a deterministically-generated held-out
evaluation set drawn from a DIFFERENT distribution than the telemetry the agent
sees, and an F1 scorer. Kept separate from the agent-facing environment so the
held-out labels are never visible during solving.

Difficulty design (inherited from CTI-REALM's detection-rule task, arXiv
2603.13517): the rule is authored against one network's telemetry but graded on
a held-out network with different C2 domains and beacon variants, plus hard
negatives that each share exactly one behavioral field with the beacon. Only a
rule that captures the behavioral intersection (URI structure AND the beacon's
User-Agent token) and does not overfit to literals/domains reaches F1 = 1.0:
  - a single-field rule flags a hard negative -> precision < 1,
  - a domain/literal-anchored rule misses the held-out variants -> recall < 1.
"""
from __future__ import annotations

import re

# --- Beacon invariant (held-out uses different domains/hex/token literals) ---
BEACON_UA = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

BANNED_FIELDS = {"dst_domain", "dst_ip", "destination", "dest_domain", "domain", "ip", "dstip"}
_ALLOWED_CONDITION_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789_ ()*")


def _hex8(i: int) -> str:
    return format((i * 2654435761) & 0xFFFFFFFF, "08x")


def _token(i: int, n: int = 22) -> str:
    x = (i * 2654435761) & 0xFFFFFFFF
    out = []
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(ALPH[x % len(ALPH)])
    return "".join(out)


# ---------------------------------------------------------------------------
# Sigma matcher
# ---------------------------------------------------------------------------
def _apply_modifier(field_value, mod: str, target) -> bool:
    fv = str(field_value)
    tv = str(target)
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


def _match_field(event: dict, key: str, target) -> bool:
    parts = key.split("|")
    field = parts[0]
    mod = parts[1] if len(parts) > 1 else ""
    if field not in event:
        return False
    values = target if isinstance(target, list) else [target]
    return any(_apply_modifier(event[field], mod, v) for v in values)


def _match_block(event: dict, block: dict) -> bool:
    if not isinstance(block, dict):
        return False
    return all(_match_field(event, k, v) for k, v in block.items())


def _eval_condition(condition: str, block_bools: dict) -> bool:
    c = str(condition).strip().lower()
    if c in ("1 of them", "1 of selection*"):
        return any(block_bools.values())
    if c == "all of them":
        return all(block_bools.values())
    if any(ch not in _ALLOWED_CONDITION_CHARS for ch in c):
        return False
    ns = {name.lower(): bool(val) for name, val in block_bools.items()}
    try:
        return bool(eval(c, {"__builtins__": {}}, ns))  # noqa: S307 - sanitized, bool-only namespace
    except Exception:
        return False


def validate(rule) -> tuple[bool, str]:
    """Structural validity plus the destination-field ban."""
    if not isinstance(rule, dict):
        return False, "rule is not a mapping"
    logsource = rule.get("logsource")
    if not isinstance(logsource, dict) or str(logsource.get("category", "")).lower() != "proxy":
        return False, "logsource.category must be 'proxy'"
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        return False, "missing detection block"
    if "condition" not in detection:
        return False, "detection.condition is required"
    blocks = {k: v for k, v in detection.items() if k != "condition"}
    if not blocks:
        return False, "no selection blocks"
    for block in blocks.values():
        if isinstance(block, dict):
            for key in block:
                if key.split("|")[0].strip().lower() in BANNED_FIELDS:
                    return False, "rule references a destination domain/IP field (banned)"
    return True, "ok"


def match_event(rule: dict, event: dict) -> bool:
    detection = rule["detection"]
    blocks = {k: v for k, v in detection.items() if k != "condition"}
    block_bools = {name: _match_block(event, blk) for name, blk in blocks.items()}
    return _eval_condition(detection["condition"], block_bools)


# ---------------------------------------------------------------------------
# Held-out evaluation set (network B: different domains/literals, same invariant)
# ---------------------------------------------------------------------------
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
NORMAL_PATHS = ["/", "/index.html", "/api/v1/status", "/assets/app.js", "/login", "/search?q=x", "/dashboard"]
HELDOUT_C2 = ["static-cache-edge.org", "ns3-analytics.co", "cdn-metrics-hub.net"]
HELDOUT_HOSTS = ["ws-finance-09", "ws-dev-21", "ws-sales-03"]


def _event(host, domain, uri, ua, code=200, size=140, method="GET"):
    return {
        "src_host": host, "dst_domain": domain, "uri_path": uri,
        "user_agent": ua, "http_method": method,
        "response_code": code, "response_bytes": size,
    }


def build_heldout() -> list[tuple[dict, int]]:
    """Return [(event, label)] for the hidden held-out network. Deterministic."""
    ev = []

    # Positives: beacon variants across multiple C2 domains and hosts, with
    # different hex/token literals than the visible network.
    for i in range(40):
        dom = HELDOUT_C2[i % len(HELDOUT_C2)]
        host = HELDOUT_HOSTS[i % len(HELDOUT_HOSTS)]
        uri = f"/{_hex8(9000 + i)}/{_token(9000 + i)}"
        ev.append((_event(host, dom, uri, BEACON_UA, 200, 120 + (i * 7) % 60), 1))

    # Hard negative A: shares the beacon User-Agent but uses ordinary URIs
    # (a legacy monitoring agent). Defeats a User-Agent-only rule.
    for i in range(40):
        host = HELDOUT_HOSTS[i % len(HELDOUT_HOSTS)]
        uri = NORMAL_PATHS[i % len(NORMAL_PATHS)]
        ev.append((_event(host, "internal-monitor.local", uri, BEACON_UA, 200, 900 + i), 0))

    # Hard negative B: shares the beacon URI structure but uses an ordinary
    # User-Agent (a benign analytics/CDN service). Defeats a URI-only rule.
    for i in range(40):
        host = HELDOUT_HOSTS[i % len(HELDOUT_HOSTS)]
        uri = f"/{_hex8(5000 + i)}/{_token(5000 + i)}"
        ua = NORMAL_UAS[i % len(NORMAL_UAS)]
        ev.append((_event(host, "metrics-beacon-cdn.io", uri, ua, 200, 1400 + i), 0))

    # General benign noise.
    for i in range(200):
        host = HELDOUT_HOSTS[i % len(HELDOUT_HOSTS)]
        uri = NORMAL_PATHS[i % len(NORMAL_PATHS)]
        ua = NORMAL_UAS[i % len(NORMAL_UAS)]
        ev.append((_event(host, "example.com", uri, ua, 200, 800 + (i * 13) % 5000), 0))

    return ev


def score(rule) -> dict:
    """Compute precision/recall/F1 of a parsed Sigma rule over the held-out set."""
    ok, reason = validate(rule)
    if not ok:
        return {"valid": False, "reason": reason, "precision": 0.0, "recall": 0.0, "f1": 0.0}

    events = build_heldout()
    tp = fp = fn = 0
    for event, label in events:
        pred = match_event(rule, event)
        if pred and label:
            tp += 1
        elif pred and not label:
            fp += 1
        elif not pred and label:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"valid": True, "reason": "ok", "precision": precision, "recall": recall, "f1": f1,
            "tp": tp, "fp": fp, "fn": fn}
