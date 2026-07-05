"""
Deterministic generator for sigma-rule-authoring-c2-beacon.

Writes the telemetry the agent authors against ($TASK_ROOT/data):
  - proxy_logs.csv  -- one week of HTTP proxy logs for "network A", ~2.5k rows.
  - beacon_description.txt -- an imprecise analyst note with a couple of seed
    request timestamps but no exact fingerprint.

The beacon here shares the SAME behavioral invariant as the hidden held-out set
in tests/sigma_verifier.py (URI = /<8-hex>/<22-char token> AND User-Agent
contains the "MSIE 10.0" token), but uses different C2 domains and hex/token
literals. The visible logs deliberately include both hard negatives so that an
agent who iterates with the harness can discover that a single-field rule
over-matches:
  - a legacy monitoring agent that reuses the beacon User-Agent on normal URIs,
  - a benign analytics service that reuses the /<hex>/<token> URI structure.

No unseeded randomness: same output on every build.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
DATA_DIR = TASK_ROOT / "data"

BEACON_UA = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
NORMAL_PATHS = [
    "/", "/index.html", "/api/v1/status", "/assets/app.js", "/assets/style.css",
    "/login", "/search?q=quarterly", "/dashboard", "/api/v1/users", "/logout",
    "/products", "/cart", "/help", "/blog/latest",
]
NORMAL_DOMAINS = [
    "example.com", "cdn.jsdelivr.net", "api.internal.corp", "updates.vendor.com",
    "mail.corp.local", "docs.corp.local", "www.news-site.com",
]
HOSTS = ["ws-finance-04", "ws-dev-12", "ws-hr-07", "ws-sales-08", "ws-eng-02"]

WEEK_START = datetime(2026, 6, 9, 0, 0, 0)


def hex8(i: int) -> str:
    return format((i * 2654435761) & 0xFFFFFFFF, "08x")


def token(i: int, n: int = 22) -> str:
    x = (i * 2654435761) & 0xFFFFFFFF
    out = []
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(ALPH[x % len(ALPH)])
    return "".join(out)


def row(dt, host, domain, uri, ua, method="GET", code=200, size=140):
    ts = dt.strftime("%Y-%m-%dT%H:%M:%S")
    return f"{ts},{host},{domain},{uri},{ua},{method},{code},{size}"


def build_rows() -> list[tuple[datetime, str]]:
    rows: list[tuple[datetime, str]] = []

    # General benign browsing noise across the week.
    for i in range(2000):
        dt = WEEK_START + timedelta(minutes=i * 5 + (i % 7))
        host = HOSTS[i % len(HOSTS)]
        domain = NORMAL_DOMAINS[i % len(NORMAL_DOMAINS)]
        uri = NORMAL_PATHS[i % len(NORMAL_PATHS)]
        ua = NORMAL_UAS[i % len(NORMAL_UAS)]
        size = 800 + (i * 13) % 6000
        rows.append((dt, row(dt, host, domain, uri, ua, "GET", 200, size)))

    # Beacon: periodic small callbacks from a finance workstation to a C2 host
    # (network-A domain), roughly hourly with jitter, over the week.
    beacon_seed_times = []
    for i in range(160):
        dt = WEEK_START + timedelta(hours=i, minutes=(i * 17) % 11, seconds=(i * 31) % 60)
        uri = f"/{hex8(1000 + i)}/{token(1000 + i)}"
        size = 120 + (i * 7) % 60
        rows.append((dt, row(dt, "ws-finance-04", "cdn-telemetry-svc.net", uri, BEACON_UA, "GET", 200, size)))
        if i in (2, 27):
            beacon_seed_times.append(dt.strftime("%Y-%m-%dT%H:%M:%S"))

    # Hard negative A: legacy monitoring agent reuses the beacon User-Agent on
    # ordinary health-check URIs (defeats a User-Agent-only rule).
    for i in range(220):
        dt = WEEK_START + timedelta(minutes=i * 45 + 3)
        uri = ["/health", "/status", "/index.html", "/ping"][i % 4]
        size = 900 + (i * 11) % 1500
        rows.append((dt, row(dt, "ws-hr-07", "internal-monitor.local", uri, BEACON_UA, "GET", 200, size)))

    # Hard negative B: benign analytics/CDN service reuses the /<hex>/<token>
    # URI structure with a normal browser User-Agent (defeats a URI-only rule).
    for i in range(220):
        dt = WEEK_START + timedelta(minutes=i * 47 + 9)
        uri = f"/{hex8(3000 + i)}/{token(3000 + i)}"
        ua = NORMAL_UAS[i % len(NORMAL_UAS)]
        size = 1400 + (i * 19) % 3000
        rows.append((dt, row(dt, HOSTS[i % len(HOSTS)], "metrics-collector.io", uri, ua, "GET", 200, size)))

    rows.sort(key=lambda r: r[0])
    return rows, beacon_seed_times


DESCRIPTION_TEMPLATE = """Analyst triage note -- suspected C2 beacon
===========================================

A Tier-1 analyst flagged machine-like, regularly-timed outbound HTTP requests
from finance workstation ws-finance-04 and believes it is a command-and-control
(C2) beacon. The callbacks are small and periodic (with some jitter) and began
around 2026-06-09.

Two of the requests we are fairly confident belong to the beacon:
  - {seed0}
  - {seed1}

We could NOT confirm the exact destination, the User-Agent string, or the
polling interval, and we do not want a rule pinned to a single domain -- the
same implant is known to rotate its C2 infrastructure. Other tooling on the
network shares some of these traits (a monitoring agent, an analytics service),
so a rule keyed on any one attribute alone will drown in false positives.

Pin down a durable behavioral fingerprint from the logs and encode it as a
Sigma rule.
"""


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    rows, seeds = build_rows()
    header = "timestamp,src_host,dst_domain,uri_path,user_agent,http_method,response_code,response_bytes"
    lines = [header] + [line for _, line in rows]
    (DATA_DIR / "proxy_logs.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (DATA_DIR / "beacon_description.txt").write_text(
        DESCRIPTION_TEMPLATE.format(seed0=seeds[0], seed1=seeds[1]), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
