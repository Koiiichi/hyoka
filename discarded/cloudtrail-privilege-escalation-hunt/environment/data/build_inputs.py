"""
Deterministic generator for the cloudtrail-privilege-escalation-hunt task.

Produces seven daily JSON-lines CloudTrail files (one management/data event per
line) under ``$TASK_DATA_ROOT/data/cloudtrail`` covering 2026-06-01 (Mon)
through 2026-06-07 (Sun) for a small AWS org (account 123456789012). The bulk of
the stream is ordinary business-as-usual API noise from a handful of IAM users
and assumed roles; a single privilege-escalation and exfil chain is embedded in
it.

Determinism: all volume and jitter comes from a fixed-seed ``random.Random`` and
all attack/decoy events carry hardcoded ``eventID`` values, so every container
build yields byte-identical files and ``tests/test_outputs.py`` can hardcode the
exact expected event identifiers.

Embedded signal (the thing the agent must find) -- six events, all in one
assumed-role session sourced from an untrusted IP on 2026-06-04:
  1. AssumeRole            2026-06-04T02:14:41Z  ci-runner keys used from 45.133.7.20  (T1078.004 valid accounts)
  2. CreatePolicyVersion   2026-06-04T02:19:05Z  new default *:* policy version       (T1098.001 account manipulation)
  3. ListBucket            2026-06-04T02:23:12Z  enumerate sensitive PII bucket        (T1530 data from cloud storage)
  4. GetObject             2026-06-04T02:23:40Z  read PII export object                (T1530)
  5. GetObject             2026-06-04T02:24:02Z  read PII export object                (T1530)
  6. GetObject             2026-06-04T02:24:31Z  read PII export object                (T1530)

Decoys (realistic look-alikes that must NOT be flagged):
  - A benign one-off ``CreatePolicyVersion`` by admin user ``dave`` from the
    corporate office IP during business hours (same API call as step 2).
  - A benign quarterly IAM audit by ``security-audit-role`` (lots of read-only
    iam:Get*/List* from a trusted contractor IP).
  - A benign high-volume ``GetObject`` batch by ``data-export-role`` against a
    NON-sensitive analytics bucket (resembles the exfil volume, wrong target).
  - Benign application reads of the sensitive PII bucket by ``app-runtime-role``
    from inside the VPC (same target bucket, legitimate principal/session).
"""
from __future__ import annotations

import json
import os
import random
import uuid
from pathlib import Path

DATA_ROOT = Path(os.environ.get("TASK_DATA_ROOT", "/root"))
OUT_DIR = DATA_ROOT / "data" / "cloudtrail"

ACCOUNT = "123456789012"
REGION = "us-east-1"
NS = uuid.UUID("6f1c9d2e-3a4b-5c6d-7e8f-90a1b2c3d4e5")

DATES = [
    "2026-06-01",
    "2026-06-02",
    "2026-06-03",
    "2026-06-04",
    "2026-06-05",
    "2026-06-06",
    "2026-06-07",
]

CORP_IPS = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"]
VPC_IPS = ["10.0.3.10", "10.0.3.11", "10.0.4.20", "10.0.4.21", "10.0.5.5"]
CI_EGRESS_IP = "198.51.100.20"
AUDIT_IP = "198.51.100.30"
ATTACKER_IP = "45.133.7.20"

NONSENSITIVE_BUCKETS = [
    "acme-app-assets",
    "acme-build-artifacts",
    "acme-analytics-logs",
    "acme-public-web",
]
SENSITIVE_BUCKET = "acme-customer-pii-prod"

UA_CLI = "aws-cli/2.13.25 Python/3.11.6 Linux/6.2.0 exe/x86_64.ubuntu.22 prompt/off"
UA_SDK_GO = "aws-sdk-go/1.44.290 (go1.20.5; linux; amd64)"
UA_BOTO = "Boto3/1.28.17 Python/3.11.4 Linux/5.15 Botocore/1.31.17"
UA_CONSOLE = "AWS Internal console.amazonaws.com"
UA_ATTACKER = "python-requests/2.31.0"

USER_KEYS = {
    "alice": "AKIAALICE0000000DEV1",
    "bob": "AKIABOB000000000DEV2",
    "carol": "AKIACAROL00000DATAE1",
    "dave": "AKIADAVE00000ADMIN01",
    "erin": "AKIAERIN00000SECOP01",
    "ci-runner": "AKIACIRUNNER00000001",
}

# Fixed identifiers for the embedded attack chain (ground truth for the verifier).
ATTACK_SESSION_KEY = "ASIAATTACKER00SESSN1"
ASSUME_ID = "a11ac1d0-0001-4a01-8b01-c100000000a1"
CPV_ID = "a11ac1d0-0002-4a01-8b01-c100000000a2"
LISTB_ID = "a11ac1d0-0003-4a01-8b01-c100000000a3"
GET1_ID = "a11ac1d0-0004-4a01-8b01-c100000000a4"
GET2_ID = "a11ac1d0-0005-4a01-8b01-c100000000a5"
GET3_ID = "a11ac1d0-0006-4a01-8b01-c100000000a6"

# Fixed identifiers for notable decoys (referenced by the verifier's decoy test).
DEC_ADMIN_CPV_ID = "dec0de00-0001-4d01-8e01-f00000000d01"
DEC_PII_READ_ID = "dec0de00-0002-4d01-8e01-f00000000d02"
DEC_ANALYTICS_ID = "dec0de00-0003-4d01-8e01-f00000000d03"
DEC_AUDIT_ID = "dec0de00-0004-4d01-8e01-f00000000d04"

rng = random.Random(20260601)
_counter = 0


def bid() -> str:
    """Return a deterministic benign event UUID derived from a running counter."""
    global _counter
    _counter += 1
    return str(uuid.uuid5(NS, f"benign-{_counter}"))


def asia() -> str:
    """Return a deterministic assumed-role (temporary) access key id."""
    body = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
    return "ASIA" + body


def t(date: str, h: int, m: int, s: int) -> str:
    """Format an ISO-8601 UTC CloudTrail eventTime."""
    return f"{date}T{h:02d}:{m:02d}:{s:02d}Z"


def rand_time(date: str, hlo: int = 8, hhi: int = 19) -> str:
    """Return a random business-hours timestamp on the given date."""
    return t(date, rng.randint(hlo, hhi), rng.randint(0, 59), rng.randint(0, 59))


def iam_user_identity(name: str) -> dict:
    """Build a userIdentity block for a long-term IAM user principal."""
    return {
        "type": "IAMUser",
        "principalId": "AIDA" + name.upper().replace("-", "")[:12],
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "accountId": ACCOUNT,
        "accessKeyId": USER_KEYS[name],
        "userName": name,
    }


def assumed_role_identity(role: str, session: str, akid: str, creation: str) -> dict:
    """Build a userIdentity block for an assumed-role (temporary credential) principal."""
    return {
        "type": "AssumedRole",
        "principalId": f"AROA{role.upper().replace('-', '')[:12]}:{session}",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session}",
        "accountId": ACCOUNT,
        "accessKeyId": akid,
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": f"AROA{role.upper().replace('-', '')[:12]}",
                "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}",
                "accountId": ACCOUNT,
                "userName": role,
            },
            "attributes": {"creationDate": creation, "mfaAuthenticated": "false"},
        },
    }


def ev(
    time_str: str,
    source: str,
    name: str,
    ip: str,
    ua: str,
    identity: dict,
    req=None,
    resp=None,
    read_only: bool = True,
    eid: str | None = None,
) -> dict:
    """Assemble a single CloudTrail-style event record."""
    return {
        "eventVersion": "1.09",
        "eventTime": time_str,
        "eventSource": source,
        "eventName": name,
        "awsRegion": REGION,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "userIdentity": identity,
        "requestParameters": req,
        "responseElements": resp,
        "readOnly": read_only,
        "eventID": eid or bid(),
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT,
    }


def s3_bucket_req(bucket: str, key: str | None = None) -> dict:
    """Build requestParameters for an S3 API call."""
    req = {"bucketName": bucket}
    if key is not None:
        req["key"] = key
    return req


def benign_events() -> list[dict]:
    """Generate the week of business-as-usual API noise across all principals."""
    out: list[dict] = []

    for date in DATES:
        # Developer activity: S3 reads/writes on non-sensitive buckets plus EC2 describes.
        for _ in range(rng.randint(190, 240)):
            dev = rng.choice(["alice", "bob"])
            ip = rng.choice(CORP_IPS)
            ua = rng.choice([UA_CLI, UA_CONSOLE])
            roll = rng.random()
            if roll < 0.45:
                bucket = rng.choice(["acme-app-assets", "acme-build-artifacts"])
                out.append(
                    ev(rand_time(date), "s3.amazonaws.com", "GetObject", ip, ua,
                       iam_user_identity(dev),
                       req=s3_bucket_req(bucket, f"builds/{rng.randint(1000, 9999)}.tar.gz"),
                       read_only=True))
            elif roll < 0.7:
                bucket = rng.choice(["acme-app-assets", "acme-public-web"])
                out.append(
                    ev(rand_time(date), "s3.amazonaws.com", "PutObject", ip, ua,
                       iam_user_identity(dev),
                       req=s3_bucket_req(bucket, f"assets/{rng.randint(1000, 9999)}.js"),
                       read_only=False))
            elif roll < 0.85:
                out.append(
                    ev(rand_time(date), "ec2.amazonaws.com", "DescribeInstances", ip, ua,
                       iam_user_identity(dev), req={"maxResults": 100}, read_only=True))
            else:
                out.append(
                    ev(rand_time(date), "logs.amazonaws.com", "GetLogEvents", ip, ua,
                       iam_user_identity(dev),
                       req={"logGroupName": f"/aws/app/{rng.choice(['api', 'worker'])}"},
                       read_only=True))

        # CI pipeline: ci-runner assumes ci-deploy-role many times/day, always from CI egress.
        for _ in range(rng.randint(14, 20)):
            session = f"ci-build-{rng.randint(100000, 999999)}"
            akid = asia()
            creation = rand_time(date, 0, 23)
            out.append(
                ev(creation, "sts.amazonaws.com", "AssumeRole", CI_EGRESS_IP, UA_SDK_GO,
                   iam_user_identity("ci-runner"),
                   req={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/ci-deploy-role",
                        "roleSessionName": session},
                   resp={"credentials": {"accessKeyId": akid, "expiration": "..."}},
                   read_only=False))
            for _ in range(rng.randint(6, 12)):
                op = rng.random()
                if op < 0.6:
                    out.append(
                        ev(rand_time(date, 0, 23), "s3.amazonaws.com", rng.choice(["GetObject", "PutObject"]),
                           CI_EGRESS_IP, UA_SDK_GO,
                           assumed_role_identity("ci-deploy-role", session, akid, creation),
                           req=s3_bucket_req("acme-build-artifacts", f"artifacts/{rng.randint(1000, 9999)}.zip"),
                           read_only=False))
                else:
                    out.append(
                        ev(rand_time(date, 0, 23), "ecr.amazonaws.com",
                           rng.choice(["GetDownloadUrlForLayer", "BatchGetImage", "PutImage"]),
                           CI_EGRESS_IP, UA_SDK_GO,
                           assumed_role_identity("ci-deploy-role", session, akid, creation),
                           req={"repositoryName": "acme/service"}, read_only=False))

        # Application runtime: app-runtime-role serves assets and legitimately reads a
        # small number of records from the sensitive PII bucket from inside the VPC.
        for _ in range(rng.randint(90, 130)):
            session = f"i-{rng.randint(10 ** 15, 10 ** 16):016x}"[:19]
            akid = asia()
            creation = rand_time(date, 0, 23)
            ip = rng.choice(VPC_IPS)
            out.append(
                ev(rand_time(date, 0, 23), "s3.amazonaws.com", "GetObject", ip, UA_BOTO,
                   assumed_role_identity("app-runtime-role", session, akid, creation),
                   req=s3_bucket_req("acme-app-assets", f"static/{rng.randint(1000, 9999)}.png"),
                   read_only=True))

        for _ in range(rng.randint(2, 4)):
            session = f"i-{rng.randint(10 ** 15, 10 ** 16):016x}"[:19]
            akid = asia()
            creation = rand_time(date, 8, 18)
            ip = rng.choice(VPC_IPS)
            out.append(
                ev(rand_time(date, 8, 18), "s3.amazonaws.com", "GetObject", ip, UA_BOTO,
                   assumed_role_identity("app-runtime-role", session, akid, creation),
                   req=s3_bucket_req(SENSITIVE_BUCKET, f"profiles/user_{rng.randint(1000, 9999)}.json"),
                   read_only=True))

        # Data engineering: data-export-role batch reads from the analytics bucket.
        for _ in range(rng.randint(55, 80)):
            session = f"export-{rng.randint(1000, 9999)}"
            akid = asia()
            creation = rand_time(date, 1, 6)
            out.append(
                ev(rand_time(date, 1, 6), "s3.amazonaws.com", rng.choice(["GetObject", "ListBucket"]),
                   rng.choice(VPC_IPS), UA_BOTO,
                   assumed_role_identity("data-export-role", session, akid, creation),
                   req=s3_bucket_req("acme-analytics-logs", f"events/{date}/part-{rng.randint(0, 200):04d}.parquet"),
                   read_only=True))

        # Security: read-only IAM posture checks by erin.
        for _ in range(rng.randint(10, 18)):
            out.append(
                ev(rand_time(date, 8, 18), "iam.amazonaws.com",
                   rng.choice(["ListUsers", "GetAccountSummary", "ListRoles", "GenerateCredentialReport"]),
                   rng.choice(CORP_IPS), UA_CLI, iam_user_identity("erin"),
                   req=None, read_only=True))

        # Admin: dave performs occasional benign infrastructure describes.
        for _ in range(rng.randint(6, 12)):
            out.append(
                ev(rand_time(date, 8, 18), "ec2.amazonaws.com",
                   rng.choice(["DescribeSecurityGroups", "DescribeVolumes", "DescribeSnapshots"]),
                   rng.choice(CORP_IPS), UA_CONSOLE, iam_user_identity("dave"),
                   req={"maxResults": 100}, read_only=True))

    return out


def decoy_events() -> list[dict]:
    """Generate the fixed-id benign look-alikes that must not be flagged."""
    out: list[dict] = []

    # Decoy 1: benign one-off CreatePolicyVersion by admin dave, business hours, corp IP.
    out.append(
        ev(t("2026-06-02", 14, 12, 33), "iam.amazonaws.com", "CreatePolicyVersion",
           CORP_IPS[0], UA_CONSOLE, iam_user_identity("dave"),
           req={"policyArn": f"arn:aws:iam::{ACCOUNT}:policy/app-readonly-policy", "setAsDefault": True},
           resp={"policyVersion": {"versionId": "v7", "isDefaultVersion": True}},
           read_only=False, eid=DEC_ADMIN_CPV_ID))

    # Decoy 2: benign application read of the sensitive PII bucket (legitimate principal).
    dec_session = "i-0a1b2c3d4e5f60718"
    dec_akid = asia()
    out.append(
        ev(t("2026-06-02", 10, 45, 9), "s3.amazonaws.com", "GetObject",
           VPC_IPS[0], UA_BOTO,
           assumed_role_identity("app-runtime-role", dec_session, dec_akid, t("2026-06-02", 10, 40, 0)),
           req=s3_bucket_req(SENSITIVE_BUCKET, "profiles/user_4821.json"),
           read_only=True, eid=DEC_PII_READ_ID))

    # Decoy 3: benign high-volume export against a NON-sensitive analytics bucket.
    dec3_session = "export-9001"
    dec3_akid = asia()
    out.append(
        ev(t("2026-06-05", 3, 15, 2), "s3.amazonaws.com", "GetObject",
           VPC_IPS[1], UA_BOTO,
           assumed_role_identity("data-export-role", dec3_session, dec3_akid, t("2026-06-05", 3, 0, 0)),
           req=s3_bucket_req("acme-analytics-logs", "events/2026-06-05/part-0142.parquet"),
           read_only=True, eid=DEC_ANALYTICS_ID))

    # Decoy 4: benign quarterly IAM audit (read-only) by security-audit-role.
    audit_session = "quarterly-audit-q2"
    audit_akid = asia()
    audit_creation = t("2026-06-03", 9, 0, 0)
    out.append(
        ev(t("2026-06-03", 9, 5, 44), "iam.amazonaws.com", "GetPolicyVersion",
           AUDIT_IP, UA_CLI,
           assumed_role_identity("security-audit-role", audit_session, audit_akid, audit_creation),
           req={"policyArn": f"arn:aws:iam::{ACCOUNT}:policy/ci-deploy-policy", "versionId": "v3"},
           read_only=True, eid=DEC_AUDIT_ID))
    for i in range(40):
        out.append(
            ev(t("2026-06-03", 9, 6 + i // 6, (i * 7) % 60), "iam.amazonaws.com",
               rng.choice(["ListPolicies", "GetPolicy", "ListAttachedRolePolicies", "ListEntitiesForPolicy"]),
               AUDIT_IP, UA_CLI,
               assumed_role_identity("security-audit-role", audit_session, audit_akid, audit_creation),
               req=None, read_only=True))

    return out


def attack_events() -> list[dict]:
    """Generate the six embedded privilege-escalation and exfil chain events."""
    out: list[dict] = []
    attacker_session = "i-0deadbeefcafe0001"
    creation = t("2026-06-04", 2, 14, 41)
    identity = assumed_role_identity("ci-deploy-role", attacker_session, ATTACK_SESSION_KEY, creation)

    # 1. Valid accounts: ci-runner long-term keys used to assume the CI role from an untrusted IP.
    out.append(
        ev(t("2026-06-04", 2, 14, 41), "sts.amazonaws.com", "AssumeRole",
           ATTACKER_IP, UA_ATTACKER, iam_user_identity("ci-runner"),
           req={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/ci-deploy-role",
                "roleSessionName": attacker_session},
           resp={"credentials": {"accessKeyId": ATTACK_SESSION_KEY, "expiration": "..."}},
           read_only=False, eid=ASSUME_ID))

    # 2. Account manipulation: set a new default policy version granting *:*.
    out.append(
        ev(t("2026-06-04", 2, 19, 5), "iam.amazonaws.com", "CreatePolicyVersion",
           ATTACKER_IP, UA_ATTACKER, identity,
           req={"policyArn": f"arn:aws:iam::{ACCOUNT}:policy/ci-deploy-policy",
                "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
                "setAsDefault": True},
           resp={"policyVersion": {"versionId": "v9", "isDefaultVersion": True}},
           read_only=False, eid=CPV_ID))

    # 3-6. Data from cloud storage: enumerate then read the sensitive PII bucket.
    out.append(
        ev(t("2026-06-04", 2, 23, 12), "s3.amazonaws.com", "ListBucket",
           ATTACKER_IP, UA_ATTACKER, identity,
           req=s3_bucket_req(SENSITIVE_BUCKET), read_only=True, eid=LISTB_ID))
    out.append(
        ev(t("2026-06-04", 2, 23, 40), "s3.amazonaws.com", "GetObject",
           ATTACKER_IP, UA_ATTACKER, identity,
           req=s3_bucket_req(SENSITIVE_BUCKET, "exports/customers_full_2026Q2.csv"),
           read_only=True, eid=GET1_ID))
    out.append(
        ev(t("2026-06-04", 2, 24, 2), "s3.amazonaws.com", "GetObject",
           ATTACKER_IP, UA_ATTACKER, identity,
           req=s3_bucket_req(SENSITIVE_BUCKET, "exports/payment_tokens_2026Q2.csv"),
           read_only=True, eid=GET2_ID))
    out.append(
        ev(t("2026-06-04", 2, 24, 31), "s3.amazonaws.com", "GetObject",
           ATTACKER_IP, UA_ATTACKER, identity,
           req=s3_bucket_req(SENSITIVE_BUCKET, "exports/ssn_index_2026Q2.csv"),
           read_only=True, eid=GET3_ID))

    return out


def write_files(events: list[dict]) -> None:
    """Sort events into per-day JSON-lines files matching CloudTrail delivery."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    by_day: dict[str, list[dict]] = {d: [] for d in DATES}
    for e in events:
        day = e["eventTime"][:10]
        by_day[day].append(e)
    for day, day_events in by_day.items():
        day_events.sort(key=lambda e: e["eventTime"])
        path = OUT_DIR / f"events-{day}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for e in day_events:
                fh.write(json.dumps(e) + "\n")


def main() -> None:
    """Generate and write the full week of CloudTrail events."""
    events = benign_events() + decoy_events() + attack_events()
    write_files(events)


if __name__ == "__main__":
    main()
