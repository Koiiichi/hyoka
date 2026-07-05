"""
Deterministic environment builder for privesc-uac-bypass-hunt.

Confirmed OTRF template (arXiv 2604.19533). Source: empire_uac_shellapi_fodhelper
(OTRF Security-Datasets, GPL-3.0) -- a fodhelper.exe UAC bypass: the attacker
hijacks the HKCU ms-settings\\Shell\\Open\\command registry key to point at an
encoded PowerShell, then launches the auto-elevating fodhelper.exe, which runs
the payload at high integrity.

Ground truth (Sigma "UAC bypass via fodhelper" T1548.002) is cross-source: the
ms-settings\\Shell\\Open\\command registry writes (Sysmon 12/13, a needle among
~1000 benign registry events), the fodhelper.exe process launches (Sysmon 1),
and the elevated child process fodhelper spawns (Sysmon 1). flag-all-registry
drowns the needle; flag-all-process is over-broad; flagging only fodhelper
misses the registry hijack.
"""
from __future__ import annotations

import gzip
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
DATA_DIR = TASK_ROOT / "data"
RAW = Path(__file__).parent / "raw" / "fodhelper_uac_bypass.jsonl.gz"

NEW_ANCHOR = datetime(2026, 5, 6, 0, 0, 0, tzinfo=timezone.utc)
ENTITY_MAP = {
    "theshire.local": "corp.example", "mordor.local": "corp.example",
    "MORDORDC": "DC01", "WORKSTATION5": "WS-05", "WORKSTATION6": "WS-06",
    "THESHIRE": "CORP", "MORDOR": "CORP", "pgustavo": "m.ward",
}
HIJACK_KEY = "ms-settings\\shell\\open\\command"

COLUMNS = ["event_id", "timestamp", "event_code", "channel", "provider", "host",
           "user", "target_user", "image", "parent_image", "parent_process_guid",
           "command_line", "logon_type", "service_name", "service_file_name",
           "target_image", "target_object", "details", "granted_access",
           "src_ip", "dst_ip", "dst_port", "process_guid", "message"]


def obfuscate(text):
    if not isinstance(text, str):
        return text
    for a, b in ENTITY_MAP.items():
        text = text.replace(a, b)
    return text


def parse_ts(raw):
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def load_records():
    with gzip.open(RAW, "rt", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def is_malicious(rec) -> bool:
    eid = rec.get("EventID")
    if eid in (12, 13) and HIJACK_KEY in (rec.get("TargetObject") or "").lower():
        return True
    if eid == 1 and (rec.get("Image") or "").lower().endswith("fodhelper.exe"):
        return True
    if eid == 1 and (rec.get("ParentImage") or "").lower().endswith("fodhelper.exe"):
        return True
    return False


def norm(record, event_id, delta):
    def g(*keys):
        for k in keys:
            if k in record and record[k] not in (None, ""):
                return record[k]
        return None

    dt = parse_ts(record.get("@timestamp") or record.get("TimeCreated"))
    ts = (dt + delta).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if dt else None
    msg = record.get("Message", "")
    return {
        "event_id": event_id, "timestamp": ts, "event_code": record.get("EventID"),
        "channel": record.get("Channel"), "provider": g("ProviderName", "SourceName"),
        "host": obfuscate(g("Hostname") or ""), "user": obfuscate(g("SubjectUserName", "User") or ""),
        "target_user": obfuscate(g("TargetUserName") or ""), "image": obfuscate(g("Image", "SourceImage") or ""),
        "parent_image": obfuscate(g("ParentImage") or ""), "parent_process_guid": g("ParentProcessGuid"),
        "command_line": obfuscate(g("CommandLine") or ""),
        "logon_type": str(g("LogonType")) if g("LogonType") is not None else None,
        "service_name": obfuscate(g("ServiceName") or ""), "service_file_name": obfuscate(g("ServiceFileName", "ImagePath") or ""),
        "target_image": obfuscate(g("TargetImage") or ""), "target_object": obfuscate(g("TargetObject") or ""),
        "details": obfuscate(g("Details") or ""), "granted_access": g("GrantedAccess"),
        "src_ip": g("IpAddress", "SourceIp"), "dst_ip": g("DestinationIp"),
        "dst_port": str(g("DestinationPort")) if g("DestinationPort") is not None else None,
        "process_guid": g("ProcessGuid", "SourceProcessGUID"), "message": obfuscate(msg[:2000] if isinstance(msg, str) else ""),
    }


def build():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    records = load_records()
    times = [parse_ts(r.get("@timestamp") or r.get("TimeCreated")) for r in records]
    delta = NEW_ANCHOR - min(t for t in times if t is not None)

    indexed = sorted(enumerate(records), key=lambda p: (str(p[1].get("@timestamp")), p[0]))
    rows, malicious_ids = [], []
    for seq, (_, rec) in enumerate(indexed, start=1):
        eid = f"evt-{seq:05d}"
        if is_malicious(rec):
            malicious_ids.append(eid)
        rows.append(norm(rec, eid, delta))

    db = DATA_DIR / "eventlogs.db"
    if db.exists():
        db.unlink()
    conn = sqlite3.connect(str(db))
    conn.execute(f"CREATE TABLE events ({', '.join((c + ' INTEGER' if c == 'event_code' else c + ' TEXT') for c in COLUMNS)})")
    conn.executemany(f"INSERT INTO events VALUES ({', '.join(':' + c for c in COLUMNS)})", rows)
    conn.commit()
    conn.close()

    if os.environ.get("WRITE_GROUND_TRUTH") == "1":
        (DATA_DIR / "ground_truth.json").write_text(json.dumps(sorted(malicious_ids), indent=2), encoding="utf-8")
    return len(rows), len(malicious_ids)


if __name__ == "__main__":
    total, mal = build()
    print(f"events={total} malicious={mal}")
