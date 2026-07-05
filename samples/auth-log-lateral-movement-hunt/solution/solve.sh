#!/bin/bash
set -e

python3 <<'PYTHON_SCRIPT'
"""
Oracle solver for auth-log-lateral-movement-hunt.

This is a genuine (if simplified) correlation heuristic over the raw logs --
it does not hardcode the answer. It exists to prove the signal is actually
extractable from the input data, per Harbor's oracle-agent sanity check.

Heuristic, in order:
  1. Brute-force success: a user account with >=3 "Failed password" lines from
     the SAME external (non-workstation) source within a 30-minute window,
     followed by an "Accepted" line for that same user+source within 10 minutes.
  2. Lateral movement: an "Accepted" line for the compromised account on a
     DIFFERENT host, sourced from another host's own IP (per asset inventory),
     within 2 hours of the prior anchor.
  3. Privilege escalation: a "sudo: <compromised user> ... USER=root" line on
     the same host, within 2 hours of the prior anchor.
  4. Second lateral movement: an "Accepted" line for root on a DIFFERENT host,
     sourced from the privesc host's own IP, within 2 hours.
  5. Data staging: a command line containing a dump/export-like keyword with
     output redirected into a hidden path (dotfile/dir), on the same host,
     within 2 hours, run as root.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path

DATA_DIR = Path("/root/data")
LOG_DIR = DATA_DIR / "logs"
OUTPUT_FILE = Path("/root/findings.json")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port \d+ ssh2")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port \d+ ssh2")
SUDO_RE = re.compile(r"sudo: (\S+) : .*USER=root")
DUMP_RE = re.compile(r"(mysqldump|pg_dump|tar -c|cp -r).*(>|--dest=).*(/\.|/tmp/\.|hidden)", re.IGNORECASE)


def parse_ts(year: int, month_str: str, day_str: str, time_str: str) -> datetime:
    return datetime(year, MONTHS[month_str], int(day_str), *map(int, time_str.split(":")))


def load_records(year: int) -> list[dict]:
    records = []
    for log_path in sorted(LOG_DIR.glob("*.log")):
        host = log_path.stem
        for line in log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            parts = line.split(None, 4)
            month_str, day_str, time_str = parts[0], parts[1], parts[2]
            ts = parse_ts(year, month_str, day_str, time_str)
            records.append({"host": host, "ts": ts, "raw": line})
    records.sort(key=lambda r: r["ts"])
    return records


def main() -> None:
    inventory = json.loads((DATA_DIR / "asset_inventory.json").read_text(encoding="utf-8"))
    host_ips = inventory["hosts"]
    ip_to_host = {ip: host for host, ip in host_ips.items()}
    known_workstations = set(inventory["known_workstation_ips"].values())
    year = inventory["log_year"]

    records = load_records(year)
    findings = []

    # Step 1: brute-force success per (user, source_ip), source not a known workstation.
    fails_by_key: dict[tuple[str, str], list[datetime]] = {}
    brute_anchor = None
    for rec in records:
        m = FAILED_RE.search(rec["raw"])
        if not m:
            continue
        user, src = m.group(1), m.group(2)
        if src in known_workstations:
            continue
        fails_by_key.setdefault((user, src), []).append(rec["ts"])

    for rec in records:
        m = ACCEPTED_RE.search(rec["raw"])
        if not m:
            continue
        user, src = m.group(1), m.group(2)
        if src in known_workstations or src in host_ips.values():
            continue
        recent_fails = [t for t in fails_by_key.get((user, src), []) if 0 <= (rec["ts"] - t).total_seconds() <= 1800]
        if len(recent_fails) >= 3:
            brute_anchor = {"host": rec["host"], "ts": rec["ts"], "user": user, "technique": "T1110"}
            break

    if brute_anchor:
        findings.append(brute_anchor)

    # Step 2: lateral movement to a different host, sourced from a known host IP.
    lateral1 = None
    if brute_anchor:
        for rec in records:
            if rec["ts"] <= brute_anchor["ts"] or (rec["ts"] - brute_anchor["ts"]) > timedelta(hours=2):
                continue
            m = ACCEPTED_RE.search(rec["raw"])
            if not m:
                continue
            user, src = m.group(1), m.group(2)
            if user != brute_anchor["user"]:
                continue
            if src in host_ips.values() and rec["host"] != ip_to_host.get(src):
                lateral1 = {"host": rec["host"], "ts": rec["ts"], "user": user, "technique": "T1021.004"}
                break
    if lateral1:
        findings.append(lateral1)

    # Step 3: privilege escalation on the same host as lateral1.
    privesc = None
    if lateral1:
        for rec in records:
            if rec["host"] != lateral1["host"]:
                continue
            if rec["ts"] <= lateral1["ts"] or (rec["ts"] - lateral1["ts"]) > timedelta(hours=2):
                continue
            m = SUDO_RE.search(rec["raw"])
            if m and m.group(1) == lateral1["user"]:
                privesc = {"host": rec["host"], "ts": rec["ts"], "user": "root", "technique": "T1548.003"}
                break
    if privesc:
        findings.append(privesc)

    # Step 4: second lateral movement as root to a different host.
    lateral2 = None
    if privesc:
        for rec in records:
            if rec["ts"] <= privesc["ts"] or (rec["ts"] - privesc["ts"]) > timedelta(hours=2):
                continue
            m = ACCEPTED_RE.search(rec["raw"])
            if not m:
                continue
            user, src = m.group(1), m.group(2)
            if user != "root":
                continue
            if src in host_ips.values() and ip_to_host.get(src) == privesc["host"] and rec["host"] != privesc["host"]:
                lateral2 = {"host": rec["host"], "ts": rec["ts"], "user": "root", "technique": "T1021.004"}
                break
    if lateral2:
        findings.append(lateral2)

    # Step 5: data staging on the same host as lateral2.
    if lateral2:
        for rec in records:
            if rec["host"] != lateral2["host"]:
                continue
            if rec["ts"] <= lateral2["ts"] or (rec["ts"] - lateral2["ts"]) > timedelta(hours=2):
                continue
            if DUMP_RE.search(rec["raw"]):
                findings.append({"host": rec["host"], "ts": rec["ts"], "user": "root", "technique": "T1005"})
                break

    output = [
        {
            "host": f["host"],
            "timestamp": f["ts"].strftime("%Y-%m-%dT%H:%M:%S"),
            "mitre_technique": f["technique"],
        }
        for f in findings
    ]
    OUTPUT_FILE.write_text(json.dumps(output, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
PYTHON_SCRIPT
