"""
Deterministic environment builder for discovery-account-enum-hunt.

Method (confirmed OTRF template / arXiv 2604.19533): real attack recordings,
time-shifted and entity-obfuscated, loaded into a queryable SQLite database for
a no-hint hunt.

Sources (OTRF Security-Datasets, GPL-3.0), combined into one campaign:
  - empire_shell_net_localgroup_administrators
  - empire_shell_net_local_users
An operator enumerates local groups and users. The account-discovery evidence
is split across sources: the reconnaissance commands themselves (Sysmon 1,
net.exe/net1.exe with localgroup/user/group arguments) and the Windows Security
audit of group/user membership enumeration (4798/4799). Neither source alone
holds the full picture, and both live amid high-volume benign telemetry.

Ground truth = the account-discovery detections: the net.exe/net1.exe recon
process-creations plus the 4798/4799 membership-enumeration events.
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
RAW_DIR = Path(__file__).parent / "raw"
RAW_FILES = ["net_localgroup.jsonl.gz", "net_local_users.jsonl.gz"]

NEW_ANCHOR = datetime(2026, 5, 6, 0, 0, 0, tzinfo=timezone.utc)
ENTITY_MAP = {
    "theshire.local": "corp.example", "mordor.local": "corp.example",
    "MORDORDC": "DC01", "WORKSTATION5": "WS-05", "WORKSTATION6": "WS-06",
    "THESHIRE": "CORP", "MORDOR": "CORP", "pgustavo": "m.ward",
}

COLUMNS = ["event_id", "timestamp", "event_code", "channel", "provider", "host",
           "user", "target_user", "image", "parent_image", "command_line", "logon_type",
           "service_name", "service_file_name", "target_image", "target_object",
           "details", "granted_access", "src_ip", "dst_ip", "dst_port",
           "process_guid", "message"]

RECON_KEYWORDS = ("localgroup", "user", "group")


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


def load_all():
    recs = []
    for fn in RAW_FILES:
        with gzip.open(RAW_DIR / fn, "rt", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    recs.append(json.loads(line))
    return recs


def is_malicious(rec) -> bool:
    """Account/group discovery detections (Sigma T1069/T1087)."""
    eid = rec.get("EventID")
    if eid in (4798, 4799):
        return True
    if eid == 1:
        image = (rec.get("Image") or "").lower()
        cmd = (rec.get("CommandLine") or "").lower()
        if (image.endswith("\\net.exe") or image.endswith("\\net1.exe")) and any(k in cmd for k in RECON_KEYWORDS):
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
        "parent_image": obfuscate(g("ParentImage") or ""), "command_line": obfuscate(g("CommandLine") or ""),
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
    records = load_all()
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
