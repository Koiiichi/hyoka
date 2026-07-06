"""
Deterministic environment builder for psexec-lateral-hunt.

Method (same as the confirmed template / arXiv 2604.19533): a real attack
recording from OTRF Security-Datasets, deterministically time-shifted and
entity-obfuscated, loaded into a queryable SQLite database for a no-hint hunt.

Source recording: empire_psexec_dcerpc_tcp_svcctl (OTRF Security-Datasets,
GPL-3.0) -- a PsExec-style remote execution: an operator authenticates over the
network and installs a service ("Updater") whose ImagePath is an encoded
PowerShell stager, which then runs. Cross-source telemetry: Windows Security
(4624 network logon, 4697 service installed), the System log (7045 service
installed), and Sysmon (process creation).

Ground truth (Sigma/behaviour-derived) = the cross-source remote-execution
chain: the non-machine network logon that authenticated it, the suspicious
service-install events in BOTH Security (4697) and System (7045), and the
service-spawned encoded-PowerShell process. No single log or event type
contains the whole chain -- it must be correlated across Security + System +
Sysmon.
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
RAW = Path(__file__).parent / "raw" / "psexec_svcctl.jsonl.gz"

NEW_ANCHOR = datetime(2026, 5, 6, 0, 0, 0, tzinfo=timezone.utc)
ENTITY_MAP = {
    "theshire.local": "corp.example", "MORDORDC": "DC01",
    "WORKSTATION5": "WS-05", "WORKSTATION6": "WS-06", "THESHIRE": "CORP",
    "pgustavo": "m.ward",
}


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
    """Sigma/behaviour-derived label for the PsExec remote-execution chain."""
    eid = rec.get("EventID")
    svc = (rec.get("ServiceFileName") or rec.get("ImagePath") or "").lower()
    if eid in (4697, 7045) and "powershell" in svc and "enc" in svc:
        return True
    if eid == 4624 and str(rec.get("LogonType")) == "3":
        user = (rec.get("TargetUserName") or "")
        if user and not user.endswith("$") and user.upper() != "ANONYMOUS LOGON":
            return True
    if eid == 1:
        parent = (rec.get("ParentImage") or "").lower()
        cmd = (rec.get("CommandLine") or "").lower()
        if parent.endswith("services.exe") and "-enc" in cmd:
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
        "event_id": event_id,
        "timestamp": ts,
        "event_code": record.get("EventID"),
        "channel": record.get("Channel"),
        "provider": g("ProviderName", "SourceName"),
        "host": obfuscate(g("Hostname") or ""),
        "user": obfuscate(g("SubjectUserName", "User") or ""),
        "target_user": obfuscate(g("TargetUserName") or ""),
        "image": obfuscate(g("Image", "SourceImage") or ""),
        "parent_image": obfuscate(g("ParentImage") or ""),
        "command_line": obfuscate(g("CommandLine") or ""),
        "logon_type": str(g("LogonType")) if g("LogonType") is not None else None,
        "service_name": obfuscate(g("ServiceName") or ""),
        "service_file_name": obfuscate(g("ServiceFileName", "ImagePath") or ""),
        "target_image": obfuscate(g("TargetImage") or ""),
        "target_object": obfuscate(g("TargetObject") or ""),
        "details": obfuscate(g("Details") or ""),
        "granted_access": g("GrantedAccess"),
        "src_ip": g("IpAddress", "SourceIp"),
        "dst_ip": g("DestinationIp"),
        "dst_port": str(g("DestinationPort")) if g("DestinationPort") is not None else None,
        "process_guid": g("ProcessGuid", "SourceProcessGUID"),
        "message": obfuscate(msg[:2000] if isinstance(msg, str) else ""),
    }


COLUMNS = ["event_id", "timestamp", "event_code", "channel", "provider", "host",
           "user", "target_user", "image", "parent_image", "command_line", "logon_type",
           "service_name", "service_file_name", "target_image", "target_object",
           "details", "granted_access", "src_ip", "dst_ip", "dst_port",
           "process_guid", "message"]


def build():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    records = load_records()

    times = [parse_ts(r.get("@timestamp") or r.get("TimeCreated")) for r in records]
    min_ts = min(t for t in times if t is not None)
    delta = NEW_ANCHOR - min_ts

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
    conn.executemany(
        f"INSERT INTO events VALUES ({', '.join(':' + c for c in COLUMNS)})", rows
    )
    conn.commit()
    conn.close()

    if os.environ.get("WRITE_GROUND_TRUTH") == "1":
        (DATA_DIR / "ground_truth.json").write_text(
            json.dumps(sorted(malicious_ids), indent=2), encoding="utf-8"
        )
    return len(rows), len(malicious_ids)


if __name__ == "__main__":
    total, mal = build()
    print(f"events={total} malicious={mal}")
