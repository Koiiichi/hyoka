#!/bin/bash
# Lazy baseline: no change (the "nop" attempt). The security suite must fail
# because the traversal vulnerability is still present.
set -e
ROOT="${TASK_ROOT:-/root}"
: # intentionally leaves ${ROOT}/app/server.py unchanged
