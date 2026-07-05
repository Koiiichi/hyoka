#!/bin/bash
set -e

python3 <<'PYTHON_SCRIPT'
"""
Oracle solver for cloudtrail-privilege-escalation-hunt.

This is a genuine correlation heuristic over the CloudTrail stream -- it does
not hardcode the answer. It exists to prove the signal is actually extractable
from the generated data, per Harbor's oracle-agent sanity check.

Heuristic, in order:
  1. Initial access (T1078): find the single sts:AssumeRole whose sourceIPAddress
     falls OUTSIDE every trusted CIDR in the asset inventory. Every legitimate
     role assumption originates from a trusted corporate/CI/VPC address, so an
     assume-role from an untrusted address is the anomaly. Capture the temporary
     session access key it mints (responseElements.credentials.accessKeyId).
  2. Account manipulation (T1098): among events performed with that exact session
     access key, collect any IAM write/manipulation call (CreatePolicyVersion,
     AttachUserPolicy, etc.). Linking by the minted key is what distinguishes the
     attacker's privilege-escalation from an unrelated benign admin policy edit.
  3. Data from cloud storage (T1530): among events performed with that session
     access key, collect S3 ListBucket/GetObject calls whose target bucket is on
     the inventory's sensitive-bucket list. Linking by session key ignores the
     legitimate application's own reads of the same bucket.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path

DATA_ROOT = Path(os.environ.get("TASK_DATA_ROOT", "/root"))
DATA_DIR = DATA_ROOT / "data"
CLOUDTRAIL_DIR = DATA_DIR / "cloudtrail"
OUTPUT_FILE = DATA_ROOT / "findings.json"

IAM_MANIPULATION = {
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "AddUserToGroup",
    "UpdateAssumeRolePolicy",
}


def load_events() -> list[dict]:
    """Read every daily CloudTrail file and return events sorted by eventTime."""
    events: list[dict] = []
    for path in sorted(CLOUDTRAIL_DIR.glob("events-*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    events.sort(key=lambda e: e["eventTime"])
    return events


def access_key(event: dict) -> str | None:
    """Return the access key id the event was performed with, if any."""
    return event.get("userIdentity", {}).get("accessKeyId")


def main() -> None:
    inventory = json.loads((DATA_DIR / "asset_inventory.json").read_text(encoding="utf-8"))
    trusted = [ipaddress.ip_network(c) for c in inventory["trusted_cidrs"]]
    sensitive_buckets = set(inventory["sensitive_buckets"])

    def is_trusted(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in trusted)

    events = load_events()
    findings: list[dict] = []

    # Step 1: initial access -- assume-role from an untrusted source IP.
    anchor = None
    for e in events:
        if e.get("eventSource") == "sts.amazonaws.com" and e.get("eventName") == "AssumeRole":
            if not is_trusted(e.get("sourceIPAddress", "")):
                anchor = e
                break

    if anchor is None:
        OUTPUT_FILE.write_text("[]", encoding="utf-8")
        return

    findings.append({"event": anchor, "technique": "T1078.004"})
    session_key = anchor.get("responseElements", {}).get("credentials", {}).get("accessKeyId")

    if session_key:
        # Step 2: account manipulation performed with the minted session key.
        for e in events:
            if access_key(e) == session_key and e.get("eventName") in IAM_MANIPULATION:
                findings.append({"event": e, "technique": "T1098.001"})

        # Step 3: reads of a sensitive bucket performed with the minted session key.
        for e in events:
            if access_key(e) != session_key:
                continue
            if e.get("eventSource") != "s3.amazonaws.com":
                continue
            if e.get("eventName") not in ("ListBucket", "GetObject"):
                continue
            bucket = (e.get("requestParameters") or {}).get("bucketName")
            if bucket in sensitive_buckets:
                findings.append({"event": e, "technique": "T1530"})

    output = [
        {
            "event_id": f["event"]["eventID"],
            "timestamp": f["event"]["eventTime"],
            "mitre_technique": f["technique"],
        }
        for f in findings
    ]
    OUTPUT_FILE.write_text(json.dumps(output, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
PYTHON_SCRIPT
