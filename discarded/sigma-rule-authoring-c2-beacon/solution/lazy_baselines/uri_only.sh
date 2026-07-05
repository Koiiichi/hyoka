#!/bin/bash
# Lazy baseline: key only on the URI structure. Flags the benign analytics
# service that shares the /<hex>/<token> structure -> precision < 1 -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
cat > "${ROOT}/sigma_rule.yml" <<'YAML'
title: beacon uri only
logsource:
    category: proxy
detection:
    selection:
        uri_path|re: '^/[0-9a-f]{8}/[A-Za-z0-9_-]{16,32}$'
    condition: selection
YAML
