#!/bin/bash
# Oracle: the behavioral-intersection rule that generalizes to the held-out
# network. It combines the beacon's URI structure with its legacy User-Agent
# token, so neither hard negative (UA-sharer, URI-sharer) is flagged and the
# domain-agnostic regex still matches beacon variants on new C2 domains.
set -e
ROOT="${TASK_ROOT:-/root}"
cat > "${ROOT}/sigma_rule.yml" <<'YAML'
title: C2 beacon - structured callback URI from legacy MSIE client
logsource:
    category: proxy
detection:
    selection:
        uri_path|re: '^/[0-9a-f]{8}/[A-Za-z0-9_-]{16,32}$'
        user_agent|contains: 'MSIE 10.0'
    condition: selection
YAML
