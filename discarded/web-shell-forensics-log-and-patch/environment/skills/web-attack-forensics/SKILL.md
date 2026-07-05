---
name: web-attack-forensics
description: Use when correlating source-code changes (diffs/pull requests) with web server access logs to investigate file-upload abuse, web shells, and related web-application intrusions.
---

# Web Application Attack Forensics Quick Reference

General reference material for correlating a code change with web traffic. This is not specific to any one investigation and does not describe any particular attack's signature.

## Reading a web access log

Combined-log format lines look like:

```
<client_ip> - - [dd/Mon/yyyy:HH:MM:SS +0000] "<METHOD> <path> HTTP/1.1" <status> <bytes> "<referer>" "<user_agent>"
```

Fields worth extracting for analysis: source IP, method, path (and its query string), status code, response byte count, user agent, and any per-request correlation id the deployment appends (e.g. `rid=...`).

## Correlating a diff with the log

1. Read the diff first, and separate what was *added* (lines beginning with `+`) from surrounding context that was merely shown. A newly introduced weakness lives in the added code; unchanged context may describe code that is already safe.
2. For any upload feature, work out from the code: the exact route that accepts the upload, where the bytes are written, whether that location is reachable over HTTP, and what validation (extension checks, filename sanitisation, re-encoding) is or is not applied.
3. Use that understanding to decide which served location could actually contain attacker-controlled content, and which could not.

## General principles for separating malicious from benign

- Surface attributes (a filename, an extension, a directory, a status code, a user agent) are often shared by both benign and malicious traffic. A single-field filter usually cannot separate them; the distinguishing signal is typically a *relationship* across fields, requests, or artifacts.
- Static assets and dynamic endpoints behave differently over repeated requests. Reasoning about how a resource behaves across the log, rather than how its request line looks in isolation, is frequently what distinguishes real activity from look-alikes.
- Correlate forward from an initial action to the follow-up activity it enables, and anchor each step to a request id.

## Relevant MITRE ATT&CK techniques

General reference (not specific to any one investigation). Map an observed action to the family that best describes what it accomplished.

| Technique ID | Name | Typical signature |
|---|---|---|
| T1110 | Brute Force | Many failed authentications followed by a success from one source |
| T1078 | Valid Accounts | Use of legitimate credentials, e.g. a successful login in an unexpected context |
| T1190 | Exploit Public-Facing Application | A request that exploits a weakness in an exposed endpoint |
| T1505.003 | Server Software Component: Web Shell | Planting or accessing an attacker-controlled script under a served directory |
| T1059 | Command and Scripting Interpreter | Executing commands (the *means*; prefer the technique of the *objective* when one applies) |
| T1083 | File and Directory Discovery | Listing or searching the filesystem |
| T1033 | System Owner/User Discovery | Determining the current user/identity |
| T1552 | Unsecured Credentials | Reading credentials from files/config |
| T1105 | Ingress Tool Transfer | Downloading an additional tool/payload to the host |
| T1560 | Archive Collected Data | Compressing/archiving data prior to exfiltration |
| T1074 | Data Staged | Writing collected data to a staging location |
| T1041 | Exfiltration Over C2 Channel | Sending collected data out over the same channel |
| T1567 | Exfiltration Over Web Service | Sending collected data out to an external web service |

