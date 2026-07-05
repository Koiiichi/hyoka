---
name: secure-code-remediation
description: Use when patching a security vulnerability in a small web service so that a security test passes without breaking functional tests.
---

# Secure Code Remediation Quick Reference

General guidance for fixing a security defect under an executed test suite. Not
specific to any one vulnerability.

## Workflow

1. Read the code and locate where untrusted input reaches a sensitive operation
   (a filesystem read, a query, a command, a redirect). Not every similar-looking
   endpoint is the vulnerable one — some may already validate their input.
2. Reproduce the issue mentally against several input variants, not just the most
   obvious one. Attackers use encodings and equivalent forms.
3. Fix at the right layer. Prefer a positive model (canonicalize, then verify the
   result is within an allowed set/location) over a negative model (blocking a
   list of "bad" strings), which tends to miss variants.
4. Preserve behavior. A fix that removes or disables legitimate functionality is
   not a fix — keep the valid cases working.
5. Re-check every variant plus the legitimate cases before finishing.

## Common pitfalls with filesystem paths

- Joining a base directory with attacker-controlled input does not confine the
  result: an absolute path or `..` segments can escape the base.
- Single-pass string filtering (e.g. removing one token) is bypassable by
  encoded or nested forms.
- Canonicalizing the resolved path and confirming it stays within the intended
  base directory is a robust positive check. Framework helpers exist for this.

## Relevant references

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal").
- OWASP: input validation and canonicalization guidance.
