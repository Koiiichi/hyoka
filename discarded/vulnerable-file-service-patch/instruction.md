You are a security engineer remediating a finding in an internal file-distribution service.

The service is a small Python/Flask application at `/root/app` (entry point `/root/app/server.py`). It serves documents from a fixed content directory over HTTP. A security review found that the service can be abused to read files **outside** the intended content directory (a path-traversal / CWE-22 issue). Not every endpoint is affected — one of the download-style routes is safe and one is not.

Your job: **fix the vulnerability in place** by editing the code under `/root/app`, so that:
- no request can be used to read files outside the content directory, and
- all legitimate functionality continues to work exactly as before.

Guidelines:
- Make a targeted fix. Do not disable or delete working functionality to make the problem "go away" — a fix that breaks legitimate downloads does not pass.
- Consider the full range of traversal techniques, not just the most obvious one (relative `..` segments, absolute paths, and URL-encoded forms are all in scope).
- You may run the service and exercise it however you like while developing your fix. Python 3 and Flask are installed.

How you are graded:
- Your patched code is executed against a hidden security test suite (multiple traversal techniques must all be blocked) **and** a functional test suite (legitimate downloads, previews, and health checks must all still succeed). You pass only if every security check and every functional check passes.

There is no separate file to write — the graded artifact is the patched source under `/root/app`.
