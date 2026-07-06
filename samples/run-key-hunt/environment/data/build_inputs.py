"""
Deterministic environment builder for run-key-hunt.

Method (confirmed OTRF template / arXiv 2604.19533): a real attack recording,
time-shifted and entity-obfuscated, loaded into a queryable SQLite database for
a no-hint hunt.

Source recording: empire_persistence_registry_modification_run_keys_elevated_user
(OTRF Security-Datasets, GPL-3.0). An Empire agent installs a Run-key
persistence entry (Sysmon EventID 13, a registry value set under
...\\CurrentVersion\\Run pointing at an encoded PowerShell) and beacons to its
C2 (Sysmon EventID 3).

Ground truth = the confirmed-malicious process (the one that wrote the Run key)
and its high-signal events: the Run-key persistence write and its C2 network
connections. Registry writes and network connections both occur benignly in
volume, so flag-all-registry / flag-all-network each capture only a fragment;
the persistence write alone misses the C2 and vice versa.
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
RAW = Path(__file__).parent / "raw" / "registry_run_key.jsonl.gz"

NEW_ANCHOR = datetime(2026, 5, 6, 0, 0, 0, tzinfo=timezone.utc)
ENTITY_MAP = {
    "mordor.local": "corp.example", "theshire.local": "corp.example",
    "MORDORDC": "DC01", "WORKSTATION5": "WS-05", "WORKSTATION6": "WS-06",
    "MORDOR": "CORP", "THESHIRE": "CORP",
}

COLUMNS = ["event_id", "timestamp", "event_code", "channel", "provider", "host",
           "user", "target_user", "image", "parent_image", "command_line", "logon_type",
           "service_name", "service_file_name", "target_image", "target_object",
           "details", "granted_access", "src_ip", "dst_ip", "dst_port",
           "process_guid", "message"]


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


def rec_guid(rec):
    return rec.get("ProcessGuid") or rec.get("SourceProcessGUID")


def is_run_key(rec) -> bool:
    return rec.get("EventID") == 13 and "currentversion\\run" in (rec.get("TargetObject") or "").lower()


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
        "parent_image": obfuscate(g("ParentImage") or ""), "command_line": obfuscate(g("CommandLine") or ""),
        "logon_type": str(g("LogonType")) if g("LogonType") is not None else None,
        "service_name": obfuscate(g("ServiceName") or ""), "service_file_name": obfuscate(g("ServiceFileName", "ImagePath") or ""),
        "target_image": obfuscate(g("TargetImage") or ""), "target_object": obfuscate(g("TargetObject") or ""),
        "details": obfuscate(g("Details") or ""), "granted_access": g("GrantedAccess"),
        "src_ip": g("IpAddress", "SourceIp"), "dst_ip": g("DestinationIp"),
        "dst_port": str(g("DestinationPort")) if g("DestinationPort") is not None else None,
        "process_guid": rec_guid(record), "message": obfuscate(msg[:2000] if isinstance(msg, str) else ""),
    }


def build():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    records = load_records()

    # Pass 1: the confirmed-malicious process is the one that wrote a Run key.
    attacker_guids = {rec_guid(r) for r in records if is_run_key(r) and rec_guid(r)}

    def malicious(rec) -> bool:
        if rec_guid(rec) not in attacker_guids:
            return False
        return rec.get("EventID") == 3 or is_run_key(rec)

    times = [parse_ts(r.get("@timestamp") or r.get("TimeCreated")) for r in records]
    delta = NEW_ANCHOR - min(t for t in times if t is not None)

    indexed = sorted(enumerate(records), key=lambda p: (str(p[1].get("@timestamp")), p[0]))
    rows, malicious_ids = [], []
    for seq, (_, rec) in enumerate(indexed, start=1):
        eid = f"evt-{seq:05d}"
        if malicious(rec):
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
