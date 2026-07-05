#!/bin/bash
# Lazy baseline: overfit to a specific URI literal observed in the visible
# network. It matches nothing on the held-out network (different hex/token
# literals) -> recall 0 -> fails. Encodes the "don't memorize literals" trap.
set -e
ROOT="${TASK_ROOT:-/root}"
# Use one concrete beacon path from the visible logs, if present.
LITERAL=$(grep -oE '/[0-9a-f]{8}/[A-Za-z0-9_-]{16,32}' "${ROOT}/data/proxy_logs.csv" | head -n1)
LITERAL="${LITERAL:-/deadbeef/AAAAAAAAAAAAAAAAAAAAAA}"
cat > "${ROOT}/sigma_rule.yml" <<YAML
title: beacon by literal path
logsource:
    category: proxy
detection:
    selection:
        uri_path|equals: '${LITERAL}'
        user_agent|contains: 'MSIE 10.0'
    condition: selection
YAML
