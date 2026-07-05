---
name: sigma-rule-authoring
description: Use when writing a Sigma detection rule against proxy/web logs, for the general YAML structure and the proxy logsource field names.
---

# Sigma Rule Authoring Quick Reference

Sigma is a generic, vendor-neutral signature format for log events. A rule is a
YAML document. This is general reference material and does not describe any
specific detection.

## Minimum useful structure

```yaml
title: Short human-readable name
logsource:
    category: proxy
detection:
    selection:
        <field>: <value>
    condition: selection
```

- `title` — a short name for the rule.
- `logsource` — narrows which events the rule applies to; for web proxy logs use
  `category: proxy`.
- `detection` — one or more named *selection* blocks plus a `condition`.
- `condition` — a boolean expression over the selection names.

## Selections and matching

A selection is a map of `field: value` clauses. Within one selection, all clauses
must match (logical AND). A value may be a single scalar or a list; a list means
"any of these" (logical OR):

```yaml
detection:
    selection:
        http_method: GET
        response_code:
            - 200
            - 204
    condition: selection
```

### Field modifiers

Append a modifier to a field name with `|`:

- `field|contains: x` — substring match.
- `field|startswith: x` — prefix match.
- `field|endswith: x` — suffix match.
- `field|re: pattern` — regular-expression match.

```yaml
        uri_path|startswith: /api/
        user_agent|contains: curl
```

## Conditions

Combine selections with `and`, `or`, `not`, and parentheses. A common pattern is
a positive match minus an exclusion:

```yaml
detection:
    selection:
        dst_domain|contains: example
    filter:
        response_code: 404
    condition: selection and not filter
```

Shorthands `all of them` and `1 of them` refer to all / any of the defined
selections.

## Proxy logsource fields (this environment)

The proxy logs in this task expose these fields (matching the CSV column names):

| Field | Meaning |
|---|---|
| `timestamp` | Request time (ISO-8601 UTC) |
| `src_host` | Internal client hostname |
| `dst_domain` | Destination hostname |
| `uri_path` | Request path (and query) |
| `user_agent` | Client User-Agent string |
| `http_method` | HTTP method (GET, POST, ...) |
| `response_code` | HTTP status code |
| `response_bytes` | Response body size in bytes |

Write field names in a rule exactly as they appear above.
