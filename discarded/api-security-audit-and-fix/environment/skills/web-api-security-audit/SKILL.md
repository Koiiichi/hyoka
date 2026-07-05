---
name: web-api-security-audit
description: Use when auditing a small web API for vulnerabilities and fixing them under an executed test suite, without regressing functionality.
---

# Web API Security Audit Quick Reference

General guidance for reviewing a web service for security defects. Not specific
to any one application; use it to reason about where a given service might be
weak.

## Audit approach

1. Enumerate every route and, for each, ask: who is allowed to call it, on
   whose data does it operate, and is that authorization actually enforced?
2. Trace untrusted input (query params, JSON bodies, headers) to every sensitive
   operation: object lookups, state changes, rendering, external calls.
3. Assume there may be more than one issue. Fixing the first one you spot is not
   the same as clearing the service.
4. Prefer fixes at the right layer, and preserve legitimate behavior — removing
   or disabling a feature is not a fix.

## Common web API weakness classes (OWASP-aligned)

- Broken object-level authorization (IDOR): an endpoint returns or modifies a
  resource by id without checking that the caller owns/may access it.
- Broken function-level authorization: a privileged action is reachable by an
  under-privileged caller.
- Mass assignment: an update endpoint copies client-supplied fields directly
  onto a stored object, letting a caller set fields they should not control
  (e.g. role/privilege flags). Whitelisting updatable fields prevents this.
- Injection, including server-side template injection (SSTI): user input that
  is evaluated as code/query/template. Passing user input as *data* (a bound
  parameter/variable) rather than concatenating it into the executed text is the
  robust fix.
- Sensitive data exposure through verbose responses or error messages.

## References

- OWASP API Security Top 10.
- CWE-639 (IDOR), CWE-915 (mass assignment), CWE-1336 / CWE-94 (template
  injection / code injection), CWE-285 (improper authorization).
