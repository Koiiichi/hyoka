---
name: mitre-attack-reference
description: Use when mapping observed AWS CloudTrail events to MITRE ATT&CK technique IDs during cloud threat hunting or detection engineering tasks.
---

# MITRE ATT&CK Quick Reference (Cloud / CloudTrail)

A short lookup of common Enterprise ATT&CK techniques relevant to AWS CloudTrail analysis. This is general reference material, not specific to any one investigation.

| Technique ID | Name | Typical CloudTrail signature |
|---|---|---|
| T1078 | Valid Accounts | A legitimate identity or key used in an unexpected context (unusual `sourceIPAddress`, `userAgent`, or hour). Sub-technique `.004` covers Cloud Accounts. |
| T1098 | Account Manipulation | IAM writes that broaden access: `CreatePolicyVersion` (+`setAsDefault`), `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `UpdateAssumeRolePolicy`, `CreateAccessKey`. Sub-technique `.001` covers Additional Cloud Credentials. |
| T1530 | Data from Cloud Storage | `s3:ListBucket` / `s3:GetObject` against a sensitive bucket, especially at a volume or by a principal inconsistent with baseline. |
| T1580 | Cloud Infrastructure Discovery | `Describe*` / `List*` enumeration across EC2, IAM, S3. |
| T1537 | Transfer Data to Cloud Account | Copying/sharing data to an external account (e.g. `ModifySnapshotAttribute`, cross-account bucket sharing). |
| T1136 | Create Account | Unexpected `CreateUser` / `CreateLoginProfile`. |
| T1070 | Indicator Removal | `StopLogging`, `DeleteTrail`, `DeleteFlowLogs`, log/history tampering. |

Notes on correlation in CloudTrail:
1. Establish a baseline of normal activity per principal (which `sourceIPAddress` ranges, user agents, hours, and buckets are normal for each user/role).
2. Look for an initial-access anomaly (a credential or role used from a context that doesn't fit its baseline).
3. When a role is assumed, the `AssumeRole` event's `responseElements.credentials.accessKeyId` is the temporary key used by every subsequent call in that session. Correlate follow-on activity by that `accessKeyId` (and `userIdentity.sessionContext`) rather than by IP alone.
4. Note any access-broadening IAM change and any sensitive-data access after that point.
5. Anchor each step to its `eventID` and the most fitting technique ID above — a top-level technique ID (e.g. `T1078`) is acceptable even if the exact sub-technique is uncertain.
