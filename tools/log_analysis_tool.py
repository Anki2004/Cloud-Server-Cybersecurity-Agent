from crewai_tools import BaseTool
import re
from collections import Counter
from logger import get_logger

logger = get_logger(__name__)


class LogAnalysisTool(BaseTool):
    name: str = "System Log Analyzer"
    description: str = (
        "Reads cloud server log files (comma-separated paths like "
        "'/var/log/auth.log,/var/log/syslog') and detects suspicious "
        "patterns such as brute force attacks, SSH root attempts, "
        "privilege escalation, and malware process execution."
    )

    SIGNATURES = {
        "brute_force_ssh": r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
        "ssh_root_attempt": r"Failed password for root from (\d+\.\d+\.\d+\.\d+)",
        "privilege_escalation": r"sudo:.*FAILED|authentication failure.*user=(\w+)",
        "successful_root_login": r"Accepted password for root from (\d+\.\d+\.\d+\.\d+)",
        "malware_process": r"(nc |ncat|netcat|mimikatz|msfconsole|wget http|curl http.*\.sh)",
        "new_account_created": r"useradd|new user.*name=(\w+)",
        "cron_modification": r"(crontab|CRON).*root",
    }

    SEVERITY_MAP = {
        "successful_root_login": "CRITICAL",
        "malware_process": "CRITICAL",
        "ssh_root_attempt": "HIGH",
        "privilege_escalation": "HIGH",
        "brute_force_ssh": "MEDIUM",
        "new_account_created": "MEDIUM",
        "cron_modification": "LOW",
    }

    def _run(self, log_paths: str) -> dict:
        paths = [p.strip() for p in log_paths.split(",")]
        all_detections = []

        for log_path in paths:
            try:
                with open(log_path, "r", errors="ignore") as f:
                    lines = f.readlines()
                logger.info(f"Scanning {len(lines)} lines from {log_path}")
            except FileNotFoundError:
                logger.warning(f"Log file not found: {log_path}")
                continue
            except PermissionError:
                logger.warning(f"Permission denied reading: {log_path}")
                continue

            for threat_name, pattern in self.SIGNATURES.items():
                matches = []
                ip_counter = Counter()

                for i, line in enumerate(lines):
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        matches.append({
                            "line_number": i + 1,
                            "content": line.strip(),
                            "captured": list(match.groups()),
                        })
                        # Count IPs for frequency analysis
                        if match.groups():
                            first_group = match.group(1) or ""
                            if re.match(r"\d+\.\d+\.\d+\.\d+", first_group):
                                ip_counter[first_group] += 1

                if matches:
                    severity = self.SEVERITY_MAP.get(threat_name, "LOW")
                    # Escalate brute force severity based on frequency
                    if threat_name == "brute_force_ssh" and len(matches) > 50:
                        severity = "HIGH"

                    all_detections.append({
                        "source_file": log_path,
                        "threat_type": threat_name,
                        "severity": severity,
                        "occurrences": len(matches),
                        "top_source_ips": ip_counter.most_common(3),
                        "sample_entries": matches[:3],
                    })
                    logger.info(f"Detected {threat_name} ({len(matches)} occurrences) in {log_path}")

        return {
            "total_threat_types_found": len(all_detections),
            "detections": all_detections,
        }
