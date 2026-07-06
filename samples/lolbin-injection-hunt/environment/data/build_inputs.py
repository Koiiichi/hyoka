"""
Deterministic environment builder for lolbin-injection-hunt.

Confirmed OTRF template (arXiv 2604.19533). Source:
covenant_lolbin_wuauclt_createremotethread (OTRF Security-Datasets, GPL-3.0).
The Windows Update client wuauclt.exe is abused as a LOLBin
(/UpdateDeploymentProvider) to load an attacker DLL and then inject into another
process via CreateRemoteThread.

Ground truth (Sigma: wuauclt LOLBin + CreateRemoteThread injection, T1055 /
T1218) = the injector's three-facet footprint, each a different Sysmon event
type: the wuauclt process creation (EventID 1), its load of a DLL from outside
C:\\Windows (EventID 7, a needle among ~180 benign image loads), and the
CreateRemoteThread (EventID 8). No single event type is the whole signal.
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
RAW = Path(__file__).parent / "raw" / "wuauclt_createremotethread.jsonl.gz"

NEW_ANCHOR = datetime(2026, 5, 6, 0, 0, 0, tzinfo=timezone.utc)
ENTITY_MAP = {
    "theshire.local": "corp.example", "mordor.local": "corp.example",
    "MORDORDC": "DC01", "WORKSTATION5": "WS-05", "WORKSTATION6": "WS-06",
    "THESHIRE": "CORP", "MORDOR": "CORP", "pgustavo": "m.ward",
}

COLUMNS = ["event_id", "timestamp", "event_code", "channel", "provider", "host",
           "user", "target_user", "image", "parent_image", "parent_process_guid",
           "command_line", "logon_type", "service_name", "service_file_name",
           "target_image", "image_loaded", "target_object", "details", "granted_access",
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


def rec_guid(rec):
    return rec.get("ProcessGuid") or rec.get("SourceProcessGuid") or rec.get("SourceProcessGUID")


def suspicious_load(rec) -> bool:
    return rec.get("EventID") == 7 and not (rec.get("ImageLoaded") or "").lower().startswith("c:\\windows")


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
        "target_image": obfuscate(g("TargetImage") or ""), "image_loaded": obfuscate(g("ImageLoaded") or ""),
        "target_object": obfuscate(g("TargetObject") or ""), "details": obfuscate(g("Details") or ""),
        "granted_access": g("GrantedAccess"), "src_ip": g("IpAddress", "SourceIp"), "dst_ip": g("DestinationIp"),
        "dst_port": str(g("DestinationPort")) if g("DestinationPort") is not None else None,
        "process_guid": rec_guid(record), "message": obfuscate(msg[:2000] if isinstance(msg, str) else ""),
    }


def build():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    records = load_records()

    # Pass 1: the injector is the source of a CreateRemoteThread (Sysmon 8).
    injectors = {rec_guid(r) for r in records if r.get("EventID") == 8 and rec_guid(r)}

    def malicious(rec) -> bool:
        if rec_guid(rec) not in injectors:
            return False
        return rec.get("EventID") in (1, 8) or suspicious_load(rec)

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
