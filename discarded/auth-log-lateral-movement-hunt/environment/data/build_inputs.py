"""
Deterministic generator for the auth-log-lateral-movement-hunt task.

Produces three syslog-style auth log files (web01, app02, db03) covering
2026-05-04 (Mon) through 2026-05-10 (Sun). Content is fully static/deterministic
(no RNG) so the ground truth in tests/test_outputs.py can be hardcoded and stays
stable across every container build.

Embedded signal (the thing the agent must find):
  1. web01 2026-05-06T02:14:41  Accepted password for deploy from 203.0.113.77 (T1110 - brute force success)
  2. app02 2026-05-06T02:24:07  Accepted publickey for deploy from 10.0.1.11    (T1021.004 - lateral movement)
  3. app02 2026-05-06T02:31:55  sudo deploy -> root                            (T1548.003 - priv esc)
  4. db03  2026-05-06T02:37:20  Accepted publickey for root from 10.0.1.12     (T1021.004 - lateral movement)
  5. db03  2026-05-06T02:40:44  mysqldump staged to hidden dir                 (T1005/T1074 - data staging)

Noise includes: daily cron jobs, legitimate engineer logins from known
workstation IPs, a couple of realistic typo-then-success benign logins, and an
unrelated external scanner (198.51.100.23) that fails against root/admin all
week and never succeeds -- a decoy that should NOT be flagged.
"""
from __future__ import annotations

from pathlib import Path

OUT_DIR = Path("/root/data/logs")

DAYS = ["04", "05", "06", "07", "08", "09", "10"]  # Mon .. Sun, May 2026
DOW = {"04": "Mon", "05": "Tue", "06": "Wed", "07": "Thu", "08": "Fri", "09": "Sat", "10": "Sun"}

MONTH = "May"


def ts(day: str, time_str: str) -> str:
    return f"{MONTH} {int(day):2d} {time_str}"


def cron_lines(host: str, pid_base: int) -> list[str]:
    lines = []
    for d in DAYS:
        lines.append(f"{ts(d, '00:05:01')} {host} CRON[{pid_base + int(d)}]: (root) CMD (/usr/lib/php/sessionclean)")
        lines.append(f"{ts(d, '04:30:00')} {host} CRON[{pid_base + int(d) + 50}]: (root) CMD (/usr/local/bin/logrotate.sh)")
    return lines


def web01_lines() -> list[str]:
    lines = []
    lines += cron_lines("web01", 10000)

    # Legit engineer logins, weekdays only, from known workstation IP.
    for d in ["04", "05", "06", "07", "08"]:
        lines.append(f"{ts(d, '09:02:14')} web01 sshd[2{d}01]: Accepted publickey for alice from 10.0.2.50 port 52344 ssh2")
        lines.append(f"{ts(d, '17:41:09')} web01 sshd[2{d}02]: pam_unix(sshd:session): session closed for user alice")

    # Benign typo-then-success (2 fails then a success from the SAME known internal IP -- not an attack).
    lines.append(f"{ts('05', '09:01:40')} web01 sshd[25010]: Failed password for alice from 10.0.2.50 port 52340 ssh2")
    lines.append(f"{ts('05', '09:01:52')} web01 sshd[25011]: Failed password for alice from 10.0.2.50 port 52341 ssh2")

    # Decoy: unrelated internet background-noise scanner, fails all week, never succeeds.
    for d in DAYS:
        for i, u in enumerate(["root", "admin", "root", "test"]):
            lines.append(
                f"{ts(d, f'{11+i:02d}:1{i}:0{i}')} web01 sshd[3{d}{i}0]: Failed password for {u} from 198.51.100.23 port 4{i}021 ssh2"
            )

    # --- Attack chain begins ---
    # Brute force against the 'deploy' service account from an external IP.
    for i, sec in enumerate([3, 47, 31, 15, 58, 22]):
        lines.append(
            f"{ts('06', f'02:1{i}:{sec:02d}')} web01 sshd[41{i}00]: Failed password for deploy from 203.0.113.77 port 5132{i} ssh2"
        )
    lines.append(f"{ts('06', '02:14:41')} web01 sshd[41599]: Accepted password for deploy from 203.0.113.77 port 51322 ssh2")
    lines.append(f"{ts('06', '02:14:41')} web01 sshd[41599]: pam_unix(sshd:session): session opened for user deploy(uid=1050) by (uid=0)")
    lines.append(f"{ts('06', '02:24:07')} web01 sshd[41610]: pam_unix(sshd:session): session opened for user deploy(uid=1050) by (uid=0)")

    return lines


def app02_lines() -> list[str]:
    lines = []
    lines += cron_lines("app02", 20000)

    for d in ["04", "05", "06", "07", "08"]:
        lines.append(f"{ts(d, '09:10:03')} app02 sshd[3{d}01]: Accepted publickey for bob from 10.0.2.51 port 41022 ssh2")
        lines.append(f"{ts(d, '18:02:44')} app02 sshd[3{d}02]: pam_unix(sshd:session): session closed for user bob")

    # A normal, legitimate sudo deploy performed by bob earlier in the week -- benign, should not be flagged.
    lines.append(f"{ts('05', '10:15:02')} app02 sudo: bob : TTY=pts/1 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart app.service")

    # --- Attack chain continues ---
    lines.append(f"{ts('06', '02:24:07')} app02 sshd[41700]: Accepted publickey for deploy from 10.0.1.11 port 40522 ssh2")
    lines.append(f"{ts('06', '02:24:07')} app02 sshd[41700]: pam_unix(sshd:session): session opened for user deploy(uid=1050) by (uid=0)")
    lines.append(f"{ts('06', '02:31:55')} app02 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
    lines.append(f"{ts('06', '02:37:20')} app02 sshd[41720]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)")

    return lines


def db03_lines() -> list[str]:
    lines = []
    lines += cron_lines("db03", 30000)

    for d in ["04", "05", "06", "07", "08"]:
        lines.append(f"{ts(d, '08:55:19')} db03 sshd[4{d}01]: Accepted publickey for carol from 10.0.2.52 port 39211 ssh2")
        lines.append(f"{ts(d, '16:20:00')} db03 sshd[4{d}02]: pam_unix(sshd:session): session closed for user carol")

    # A routine, legitimate backup job (different hour, different target dir) -- benign, should not be flagged.
    lines.append(f"{ts('06', '01:00:02')} db03 CRON[39901]: (root) CMD (/usr/local/bin/nightly_backup.sh --dest=/mnt/backups)")

    # --- Attack chain concludes ---
    lines.append(f"{ts('06', '02:37:20')} db03 sshd[41800]: Accepted publickey for root from 10.0.1.12 port 51890 ssh2")
    lines.append(f"{ts('06', '02:37:20')} db03 sshd[41800]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)")
    lines.append(f"{ts('06', '02:40:44')} db03 bash[41810]: root: mysqldump -u root customer_records > /tmp/.cache/backup_20260506.sql")

    return lines


def write_sorted(host: str, lines: list[str]) -> None:
    # Sort by (day, time) to look like a real chronological log file.
    def sort_key(line: str):
        parts = line.split()
        day = parts[1].zfill(2)
        time_str = parts[2]
        return (day, time_str)

    lines_sorted = sorted(lines, key=sort_key)
    (OUT_DIR / f"{host}.log").write_text("\n".join(lines_sorted) + "\n", encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_sorted("web01", web01_lines())
    write_sorted("app02", app02_lines())
    write_sorted("db03", db03_lines())


if __name__ == "__main__":
    main()
