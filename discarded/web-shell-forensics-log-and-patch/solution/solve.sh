#!/bin/bash
set -e

python3 <<'PYTHON_SCRIPT'
"""
Oracle for web-shell-forensics-log-and-patch (Lever-A).

Correlates the diff with the access log to reconstruct a multi-step web
intrusion and label each step with its MITRE ATT&CK technique family. Does not
hardcode the answer: it derives the vulnerable endpoint from the diff, identifies
the attacker as the principal who exploited that endpoint and then operated a
script under its public serve directory, and classifies each chain request by
its observable behaviour.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
DATA = TASK_ROOT / "data"
OUTPUT = TASK_ROOT / "findings.json"

ROUTE_RE = re.compile(r"""@app\.route\(\s*["']([^"']+)["']\s*,\s*methods\s*=\s*\[([^\]]*)\]""")
STATIC_PREFIX_RE = re.compile(r"(/static/[A-Za-z0-9_\-]+/)")
LOG_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) (\d+) "[^"]*" "[^"]*" rid=(\S+)')


def parse_diff(text):
    added = "\n".join(l[1:] for l in text.splitlines() if l.startswith("+") and not l.startswith("+++"))
    endpoint = None
    for m in ROUTE_RE.finditer(added):
        if "POST" in m.group(2).upper():
            endpoint = m.group(1)
            break
    pm = STATIC_PREFIX_RE.search(added)
    return endpoint, (pm.group(1) if pm else "/static/")


def parse_log(text):
    recs = []
    for line in text.splitlines():
        m = LOG_RE.match(line)
        if not m:
            continue
        ip, ts, method, path, status, size, rid = m.groups()
        recs.append({"ip": ip, "ts": datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z"),
                     "method": method, "path": path, "status": int(status),
                     "size": int(size), "rid": rid})
    recs.sort(key=lambda r: r["ts"])
    return recs


def only(path):
    return path.split("?", 1)[0]


def classify_shell(query: str) -> str:
    q = query.lower()
    if "curl" in q and ("post" in q or "--data" in q or "-d " in q):
        return "T1041"          # Exfiltration Over C2 Channel
    if ("wget" in q or "curl" in q) and "http" in q:
        return "T1105"          # Ingress Tool Transfer
    if any(t in q for t in ("tar ", "zip ", "gzip", "tar%20")):
        return "T1560"          # Archive Collected Data
    if "cat" in q and any(t in q for t in ("config", ".env", "passwd", "secret", "credential")):
        return "T1552"          # Unsecured Credentials: Credentials In Files
    if any(t in q for t in ("ls ", "ls%20", "dir ", "find ", "find%20")):
        return "T1083"          # File and Directory Discovery
    return "T1505"              # Server Software Component: Web Shell


def main():
    endpoint, prefix = parse_diff((DATA / "changes.diff").read_text())
    recs = parse_log((DATA / "access_log.txt").read_text())

    def is_shell(r):
        p = only(r["path"])
        return r["method"] == "GET" and r["status"] == 200 and p.startswith(prefix) and p.lower().endswith(".php")

    shell_hits = [r for r in recs if is_shell(r)]
    uploaders = {r["ip"] for r in recs if r["method"] == "POST" and only(r["path"]) == endpoint and r["status"] == 201}
    attacker_ips = {r["ip"] for r in shell_hits} & uploaders
    if not attacker_ips:
        OUTPUT.write_text("[]"); return

    findings = []

    # Brute-force success: a successful login preceded by >=3 failed logins from
    # the same attacker principal.
    for ip in attacker_ips:
        logins = [r for r in recs if r["ip"] == ip and only(r["path"]) == "/login"]
        fails = [r for r in logins if r["status"] in (401, 403)]
        for r in logins:
            if r["status"] == 200 and sum(1 for f in fails if 0 <= (r["ts"] - f["ts"]).total_seconds() <= 3600) >= 3:
                findings.append({"request_id": r["rid"], "mitre_technique": "T1110"})
                break

    # Initial code execution: the upload to the vulnerable endpoint.
    for r in recs:
        if r["ip"] in attacker_ips and r["method"] == "POST" and only(r["path"]) == endpoint and r["status"] == 201:
            findings.append({"request_id": r["rid"], "mitre_technique": "T1505"})
            break

    # Web shell lifecycle.
    for r in shell_hits:
        if r["ip"] not in attacker_ips:
            continue
        query = r["path"].split("?", 1)[1] if "?" in r["path"] else ""
        findings.append({"request_id": r["rid"], "mitre_technique": classify_shell(query)})

    OUTPUT.write_text(json.dumps(findings, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
PYTHON_SCRIPT
