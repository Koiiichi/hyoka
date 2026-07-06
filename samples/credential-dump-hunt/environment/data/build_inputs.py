"""
Deterministic environment builder for credential-dump-hunt.

Replicates the construction method of the Cyber Defense Benchmark
(arXiv 2604.19533): take a real attack recording from the OTRF Security-Datasets
corpus, deterministically time-shift and entity-obfuscate it (so it is
reproducible but not a verbatim, memorizable public file), and load it into a
queryable SQLite database. The agent must threat-hunt the database with no
hints and flag the malicious events.

Source recording (vendored under data/raw/): a real Empire + Mimikatz
credential-theft campaign captured as Windows Security + Sysmon logs
(empire_mimikatz_logonpasswords, OTRF Security-Datasets, GPL-3.0). 6026 real
events; the intrusion is a single powershell.exe process that beacons to a C2
host and reads lsass.exe memory (T1003.001 OS Credential Dumping + T1071 C2).

Ground truth (Sigma/behaviour-derived, per the paper) = the events belonging to
that confirmed-malicious process that are themselves high-signal detections:
its C2 network connections (Sysmon EventID 3) and its lsass memory reads
(Sysmon EventID 10). Computed here at build time from the ORIGINAL attacker
process GUID, before obfuscation, and written to ground_truth.json only when
WRITE_GROUND_TRUTH=1 (used once locally to populate tests/; never in-container).
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
RAW = Path(__file__).parent / "raw" / "empire_mimikatz_logonpasswords.jsonl.gz"

# The confirmed-malicious process in the original recording (the powershell that
# read lsass with GrantedAccess 0x1010 and beaconed to the C2).
ATTACKER_GUID = "{297bc33e-65d0-5f2d-8207-000000000400}"
MALICIOUS_EVENT_CODES = {3, 10}  # network connection, process access (to lsass)

# Deterministic time shift: move the 2020 recording into a fixed 2026 window.
ORIG_ANCHOR = datetime(2020, 8, 7, 0, 0, 0, tzinfo=timezone.utc)
NEW_ANCHOR = datetime(2026, 5, 6, 0, 0, 0, tzinfo=timezone.utc)
TIME_DELTA = NEW_ANCHOR - ORIG_ANCHOR

# Deterministic entity obfuscation (removes the public-dataset fingerprint while
# preserving all correlations).
ENTITY_MAP = {
    "theshire.local": "corp.example",
    "MORDORDC": "DC01",
    "WORKSTATION5": "WS-05",
    "WORKSTATION6": "WS-06",
    "THESHIRE": "CORP",
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


def shift_ts(raw):
    dt = parse_ts(raw)
    if dt is None:
        return raw
    return (dt + TIME_DELTA).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def load_records():
    with gzip.open(RAW, "rt", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def norm(record, event_id):
    def g(*keys):
        for k in keys:
            if k in record and record[k] not in (None, ""):
                return record[k]
        return None

    message = record.get("Message", "")
    return {
        "event_id": event_id,
        "timestamp": shift_ts(record.get("@timestamp") or record.get("TimeCreated")),
        "event_code": record.get("EventID"),
        "channel": record.get("Channel"),
        "provider": g("ProviderName", "SourceName"),
        "host": obfuscate(g("Hostname") or ""),
        "user": obfuscate(g("SubjectUserName", "User", "TargetUserName") or ""),
        "image": obfuscate(g("Image", "SourceImage") or ""),
        "target_image": obfuscate(g("TargetImage") or ""),
        "granted_access": g("GrantedAccess"),
        "src_ip": g("SourceIp"),
        "dst_ip": g("DestinationIp"),
        "dst_port": str(g("DestinationPort")) if g("DestinationPort") is not None else None,
        "process_guid": g("ProcessGuid", "SourceProcessGUID"),
        "message": obfuscate(message[:2000] if isinstance(message, str) else ""),
    }


def build():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    records = load_records()

    indexed = list(enumerate(records))
    indexed.sort(key=lambda pair: (str(pair[1].get("@timestamp")), pair[0]))

    rows = []
    malicious_ids = []
    for seq, (orig_idx, rec) in enumerate(indexed, start=1):
        event_id = f"evt-{seq:05d}"
        is_malicious = (
            (rec.get("ProcessGuid") == ATTACKER_GUID or rec.get("SourceProcessGUID") == ATTACKER_GUID)
            and rec.get("EventID") in MALICIOUS_EVENT_CODES
        )
        if is_malicious:
            malicious_ids.append(event_id)
        rows.append(norm(rec, event_id))

    db_path = DATA_DIR / "eventlogs.db"
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """CREATE TABLE events (
            event_id TEXT PRIMARY KEY, timestamp TEXT, event_code INTEGER,
            channel TEXT, provider TEXT, host TEXT, user TEXT, image TEXT,
            target_image TEXT, granted_access TEXT, src_ip TEXT, dst_ip TEXT,
            dst_port TEXT, process_guid TEXT, message TEXT
        )"""
    )
    conn.executemany(
        """INSERT INTO events VALUES
           (:event_id,:timestamp,:event_code,:channel,:provider,:host,:user,
            :image,:target_image,:granted_access,:src_ip,:dst_ip,:dst_port,
            :process_guid,:message)""",
        rows,
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
