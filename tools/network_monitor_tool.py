from crewai_tools import BaseTool
import subprocess
import re
from collections import Counter
from logger import get_logger

logger = get_logger(__name__)

# Ports commonly targeted in cloud server attacks
SUSPICIOUS_INBOUND_PORTS = {22, 23, 3306, 5432, 6379, 27017, 9200, 2375, 11211}

# Known malware / backdoor / C2 listening ports
BACKDOOR_PORTS = {4444, 1337, 31337, 8888, 9999, 6666, 5555}


class NetworkMonitorTool(BaseTool):
    name: str = "Network Traffic Monitor"
    description: str = (
        "Analyzes active network connections and listening services on the "
        "cloud server to detect port scans, C2 beaconing, backdoor ports, "
        "and suspicious outbound connections. No input required — pass 'scan'."
    )

    def _run(self, query: str = "scan") -> dict:
        detections = []

        # ── 1. Active established connections (ss -tnp) ───────────────────────
        try:
            result = subprocess.run(
                ["ss", "-tnp"], capture_output=True, text=True, timeout=10
            )
            connections = self._parse_ss(result.stdout)
            detections.extend(self._analyze_connections(connections))
            logger.info(f"Parsed {len(connections)} active connections")
        except Exception as e:
            logger.error(f"ss -tnp failed: {e}")

        # ── 2. Listening services (ss -tlnp) ──────────────────────────────────
        try:
            result = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=10
            )
            detections.extend(self._check_listening(result.stdout))
        except Exception as e:
            logger.error(f"ss -tlnp failed: {e}")

        # ── 3. Port scan detection from auth.log ──────────────────────────────
        try:
            with open("/var/log/auth.log", "r", errors="ignore") as f:
                content = f.read()
            ips = re.findall(r"from (\d+\.\d+\.\d+\.\d+)", content)
            ip_counts = Counter(ips)
            for ip, count in ip_counts.most_common(10):
                if count > 20:
                    detections.append({
                        "threat_type": "port_scan_or_brute_force",
                        "source_ip": ip,
                        "connection_attempts": count,
                        "severity": "HIGH" if count > 50 else "MEDIUM",
                        "detail": f"IP {ip} made {count} connection attempts — likely port scan or brute force",
                    })
        except FileNotFoundError:
            logger.warning("auth.log not found for port scan detection")
        except Exception as e:
            logger.error(f"Port scan detection error: {e}")

        return {
            "total_network_threats": len(detections),
            "detections": detections,
        }

    def _parse_ss(self, output: str) -> list:
        connections = []
        for line in output.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    "state": parts[0],
                    "local": parts[3],
                    "remote": parts[4],
                })
        return connections

    def _analyze_connections(self, connections: list) -> list:
        detections = []
        remote_ip_counter = Counter()

        for conn in connections:
            remote = conn.get("remote", "")
            port_match = re.search(r":(\d+)$", remote)
            if not port_match:
                continue

            port = int(port_match.group(1))
            ip = remote.rsplit(":", 1)[0].strip("[]")
            remote_ip_counter[ip] += 1

            if port in SUSPICIOUS_INBOUND_PORTS:
                detections.append({
                    "threat_type": "suspicious_port_connection",
                    "remote_address": remote,
                    "port": port,
                    "severity": "MEDIUM",
                    "detail": f"Active connection to sensitive service port {port} from {ip}",
                })

        # High connection count to same IP = possible C2 beaconing
        for ip, count in remote_ip_counter.items():
            if count > 10 and ip not in ("127.0.0.1", "::1"):
                detections.append({
                    "threat_type": "possible_c2_beaconing",
                    "remote_ip": ip,
                    "connection_count": count,
                    "severity": "HIGH",
                    "detail": f"Unusually high connection frequency ({count}) to {ip} — possible C2 beaconing",
                })

        return detections

    def _check_listening(self, output: str) -> list:
        detections = []
        for line in output.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            addr = parts[3]
            port_match = re.search(r":(\d+)$", addr)
            if port_match:
                port = int(port_match.group(1))
                if port in BACKDOOR_PORTS:
                    detections.append({
                        "threat_type": "backdoor_port_listening",
                        "port": port,
                        "severity": "CRITICAL",
                        "detail": f"Known backdoor/malware port {port} is actively listening on this server",
                    })
        return detections
