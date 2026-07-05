#!/bin/bash
# Lazy baseline: key only on the beacon User-Agent token. Flags the legacy
# monitoring agent that reuses it on normal URIs -> precision < 1 -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
cat > "${ROOT}/sigma_rule.yml" <<'YAML'
title: beacon ua only
logsource:
    category: proxy
detection:
    selection:
        user_agent|contains: 'MSIE 10.0'
    condition: selection
YAML
