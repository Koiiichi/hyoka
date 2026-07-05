You are a SOC analyst investigating a compromise of a public-facing web application server. All activity is from the year **2026**.

You have two artifacts under `/root/data`:
- `access_log.txt` — the web server access log (combined-log format) covering **2026-05-04 through 2026-05-08**. Every line ends with a unique request-id token of the form `rid=<id>`.
- `changes.diff` — a unified diff of a recently merged pull request. One of the changes introduced the weakness the attacker used to gain code execution; another endpoint shown in the diff is already hardened.

A single attacker carried out a multi-stage intrusion during this window: gaining access, planting a foothold, and then operating on the server. The log also contains a large volume of ordinary traffic and several benign activities that individually resemble parts of an attack (a legitimate administrator, an internet scanner, a normal feature that takes a command-style parameter, routine uploads).

Your job: reconstruct the intrusion and write it to `/root/findings.json` as a JSON list, one object per request that is part of the attack chain:

```json
[
  {"request_id": "<rid>", "mitre_technique": "<MITRE ATT&CK technique ID, e.g. T1190>"}
]
```

Requirements:
- Report **only** the requests that are genuinely part of the attacker's chain — every stage, and nothing else. A precise, minimal set is graded: a missed stage, or a benign look-alike included as a false positive, fails the task.
- For **each** reported request, give the MITRE ATT&CK technique ID that best matches what that request accomplished. The top-level technique family must be correct; a sub-technique suffix is optional.
- Use the diff to determine which endpoint actually enabled code execution — that is how you separate the real intrusion from legitimate uploads and from a scanner that probed the same endpoint but never got in.
- The stages are heterogeneous: initial access, the foothold, and the distinct post-exploitation actions each map to a *different* technique. Identify what each request does before labelling it.

A general MITRE ATT&CK reference is available in the skills directory. You have shell access and Python 3 with the standard library. This is meant to be solved by directly parsing and correlating the two artifacts.
