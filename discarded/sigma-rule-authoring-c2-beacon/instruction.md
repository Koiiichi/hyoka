You are a SOC analyst on a small corporate network (workstations `ws-finance-04`, `ws-dev-12`, `ws-hr-07`, and others). A Tier-1 analyst has flagged suspicious, machine-like outbound traffic from a finance workstation and suspects a command-and-control (C2) beacon. All activity is from the year **2026**.

Inputs, both under `/root/data`:
- `proxy_logs.csv` — one week (2026-06-09 onward) of HTTP proxy logs, roughly 2,600 rows. Columns: `timestamp,src_host,dst_domain,uri_path,user_agent,http_method,response_code,response_bytes`. The beacon's traffic is present here, mixed into realistic benign browsing, a legacy monitoring agent, and an analytics service.
- `beacon_description.txt` — the analyst's plain-English note. It is deliberately imprecise: it gives two seed requests but not the exact destination, User-Agent, or interval.

Your job: study the logs, establish the beacon's durable behavioral fingerprint, and author a **Sigma detection rule** at `/root/sigma_rule.yml`.

A helper is provided to iterate:

```
python3 /root/data/sigma_eval.py /root/sigma_rule.yml
```

It reports how many rows of `proxy_logs.csv` your current rule matches, so you can refine it. It does not reveal labels.

The rule must be valid YAML with at least:
- `title`
- `logsource:` with `category: proxy`
- `detection:` with one or more named selection blocks (field/value conditions; modifiers `|contains`, `|startswith`, `|endswith`, `|re` and value lists are supported) plus a `condition:` (e.g. `selection`, `selection and not filter`, `1 of them`).

How you are graded:
- Your rule is evaluated against a **hidden held-out capture from a different network** — different C2 domains and beacon variants, plus benign look-alikes — that you cannot see while solving. Reward is the **F1 score** over the beacon events in that held-out set. A pass requires perfect generalization (F1 = 1.0); partial rules receive partial reward.
- **Do not key on the destination.** The implant rotates its C2 infrastructure, so a rule referencing `dst_domain` (or any destination domain/IP field) cannot generalize and scores 0.
- **One field is not enough.** Benign tooling on the network deliberately shares individual traits with the beacon: a monitoring agent reuses its User-Agent, and an analytics service reuses its URI structure. A rule keyed on a single behavioral field will fire on these look-alikes in the held-out set and will not pass. An effective rule combines the behavioral attributes that, together, are unique to the beacon and hold across destinations.
- **Do not memorize literals.** Specific paths, hosts, and timestamps from these logs will not appear verbatim in the held-out capture.

You have shell access and Python 3 (with PyYAML) available. This is meant to be solved by directly parsing and correlating the proxy logs.
