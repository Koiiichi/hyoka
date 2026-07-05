You are a security engineer performing a pre-release audit of an internal team API service.

The service is a Python/Flask application at `/root/app` (entry point `/root/app/server.py`). It provides login, per-user document access, profile management, an admin-only user listing, and a greeting endpoint. The review team believes the service contains **more than one** security vulnerability, of different kinds, and none has been fixed yet.

Your job: **find and fix every vulnerability** by editing the code under `/root/app`, so that:
- no endpoint can be abused to bypass authorization, escalate privileges, access other users' data, or execute injected input, and
- all legitimate functionality continues to work exactly as before.

Guidelines:
- Audit the whole service. Fixing the first issue you notice is not enough — assume there are several, of distinct classes, and keep looking until you are confident the service is clean.
- Make targeted fixes. Do not disable or gut working features to make a problem "go away" — a fix that breaks legitimate behavior does not pass.
- You may run the service and exercise every endpoint however you like while developing your fixes. Python 3 and Flask are installed.

How you are graded:
- Your patched code is executed against a hidden security test suite (each distinct vulnerability has an exploit that must be blocked) **and** a functional test suite (login, legitimate document access, profile updates, admin listing, and greetings must all still work). You pass only if **every** security check and **every** functional check passes — fixing some but not all of the vulnerabilities does not pass.

There is no separate file to write — the graded artifact is the patched source under `/root/app`.
