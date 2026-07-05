#!/bin/bash
# Lazy baseline: anchor on the visible C2 domain. Uses a banned destination
# field (structural fail) and would miss rotated-domain variants anyway.
set -e
ROOT="${TASK_ROOT:-/root}"
cat > "${ROOT}/sigma_rule.yml" <<'YAML'
title: beacon by domain
logsource:
    category: proxy
detection:
    selection:
        dst_domain|contains: 'cdn-telemetry-svc.net'
    condition: selection
YAML
