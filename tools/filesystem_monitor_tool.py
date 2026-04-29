from crewai.tools import BaseTool
import os
import stat
from datetime import datetime, timedelta
from logger import get_logger

logger = get_logger(__name__)

# Critical system files that should never change unexpectedly
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/crontab",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/ld.so.preload",     # common malware persistence point
]

# Web shell code signatures
WEBSHELL_SIGNATURES = [
    "eval(base64_decode",
    "system($_GET",
    "exec($_POST",
    "passthru(",
    "shell_exec(",
    "<?php system(",
    "<?php exec(",
    "import os; os.system",
    "subprocess.call",
    "__import__('os').system",
]

# Common web roots on cloud servers
WEB_ROOTS = [
    "/var/www/html",
    "/var/www",
    "/srv/www",
    "/opt/app",
    "/home/ubuntu/public_html",
]

# Suspicious locations for new SUID binaries
SUID_SCAN_PATHS = [
    "/usr/local/bin",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
]

HOME_BASES = ["/root", "/home"]
TMP_SCAN_PATH = "/tmp"


class FileSystemMonitorTool(BaseTool):
    name: str = "File System Monitor"
    description: str = (
        "Monitors critical cloud server directories for unauthorized changes. "
        "Detects modified system files, web shells, new SUID binaries, "
        "and unauthorized SSH key additions. "
        "Input: number of hours to look back (e.g. '24')."
    )

    def _run(self, hours_back: str = "24") -> dict:
        try:
            hours = int(hours_back)
        except ValueError:
            hours = 24

        cutoff = datetime.now() - timedelta(hours=hours)
        detections = []

        # ── 1. Critical system file modifications ─────────────────────────────
        for filepath in CRITICAL_FILES:
            if not os.path.exists(filepath):
                continue
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                if mtime > cutoff:
                    detections.append({
                        "threat_type": "critical_system_file_modified",
                        "file": filepath,
                        "modified_at": mtime.isoformat(),
                        "severity": "CRITICAL",
                        "detail": f"Critical system file {filepath} was modified within the last {hours}h — possible persistence or credential manipulation",
                    })
                    logger.warning(f"Critical file modified: {filepath}")
            except (PermissionError, OSError) as e:
                logger.warning(f"Cannot stat {filepath}: {e}")

        # ── 2. Web shell detection ────────────────────────────────────────────
        for web_root in WEB_ROOTS:
            if not os.path.exists(web_root):
                continue
            for root, dirs, files in os.walk(web_root):
                # Skip node_modules and similar large dirs
                dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "vendor")]
                for fname in files:
                    if not fname.endswith((".php", ".py", ".jsp", ".asp", ".aspx", ".phtml")):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", errors="ignore") as f:
                            content = f.read()
                        for sig in WEBSHELL_SIGNATURES:
                            if sig.lower() in content.lower():
                                detections.append({
                                    "threat_type": "web_shell_detected",
                                    "file": fpath,
                                    "matched_signature": sig,
                                    "severity": "CRITICAL",
                                    "detail": f"Web shell signature '{sig}' found in {fpath}",
                                })
                                logger.warning(f"Web shell detected: {fpath}")
                                break
                    except (PermissionError, OSError):
                        continue

        # ── 3. New SUID binaries in suspicious locations ──────────────────────
        for scan_path in SUID_SCAN_PATHS:
            if not os.path.exists(scan_path):
                continue
            try:
                for fname in os.listdir(scan_path):
                    fpath = os.path.join(scan_path, fname)
                    try:
                        fstat = os.stat(fpath)
                        is_suid = bool(fstat.st_mode & stat.S_ISUID)
                        mtime = datetime.fromtimestamp(fstat.st_mtime)
                        if is_suid and mtime > cutoff:
                            detections.append({
                                "threat_type": "new_suid_binary",
                                "file": fpath,
                                "created_modified_at": mtime.isoformat(),
                                "severity": "HIGH",
                                "detail": f"New SUID binary found in {scan_path} — possible privilege escalation tool",
                            })
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError) as e:
                logger.warning(f"Cannot scan {scan_path}: {e}")

        # ── 4. Unauthorized SSH key additions ─────────────────────────────────
        for base in HOME_BASES:
            if not os.path.exists(base):
                continue
            try:
                entries = [base] if base == "/root" else [
                    os.path.join(base, d) for d in os.listdir(base)
                ]
                for user_home in entries:
                    auth_keys = os.path.join(user_home, ".ssh", "authorized_keys")
                    if not os.path.exists(auth_keys):
                        continue
                    try:
                        mtime = datetime.fromtimestamp(os.path.getmtime(auth_keys))
                        if mtime > cutoff:
                            detections.append({
                                "threat_type": "ssh_authorized_key_added",
                                "file": auth_keys,
                                "modified_at": mtime.isoformat(),
                                "severity": "HIGH",
                                "detail": f"SSH authorized_keys modified at {auth_keys} — possible backdoor SSH key added",
                            })
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError) as e:
                logger.warning(f"Cannot scan home dir {base}: {e}")

        # ── 5. Files in /tmp with execute permissions (malware staging) ───────
        try:
            for fname in os.listdir(TMP_SCAN_PATH):
                fpath = os.path.join(TMP_SCAN_PATH, fname)
                try:
                    fstat = os.stat(fpath)
                    mtime = datetime.fromtimestamp(fstat.st_mtime)
                    is_executable = bool(fstat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                    if is_executable and mtime > cutoff and os.path.isfile(fpath):
                        detections.append({
                            "threat_type": "executable_in_tmp",
                            "file": fpath,
                            "created_at": mtime.isoformat(),
                            "severity": "HIGH",
                            "detail": f"Executable file {fpath} found in {TMP_SCAN_PATH} — common malware staging location",
                        })
                except (PermissionError, OSError):
                    continue
        except Exception as e:
            logger.warning(f"{TMP_SCAN_PATH} scan error: {e}")

        return {
            "scan_window_hours": hours,
            "total_fs_threats": len(detections),
            "detections": detections,
        }
