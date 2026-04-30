
import re
import os
import logging

logger = logging.getLogger(__name__)

AWS_REGION    = os.getenv("AWS_REGION", "ap-south-1")
SG_NAME       = os.getenv("SOAR_SG_NAME", "multi-agent-cybersec-sg")

# Private/internal IP ranges to never block
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def _extract_ips(report: str) -> list[str]:
    """Extract unique public IPs from report text."""
    all_ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', report)
    seen = set()
    public = []
    for ip in all_ips:
        if ip not in seen and not _is_private(ip):
            seen.add(ip)
            public.append(ip)
    return public


def _get_sg_id(ec2_client, sg_name: str) -> str | None:
    try:
        resp = ec2_client.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [sg_name]}]
        )
        sgs = resp.get("SecurityGroups", [])
        if sgs:
            return sgs[0]["GroupId"]
    except Exception as e:
        logger.error(f"SOAR: Failed to get SG ID: {e}")
    return None


def block_ip(ec2_client, sg_id: str, ip: str) -> bool:
    """Add deny-all ingress rule for a single IP."""
    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{
                    "CidrIp": f"{ip}/32",
                    "Description": "Auto-blocked by SOAR — cybersec agent"
                }]
            }]
        )
        logger.warning(f"SOAR: Blocked IP {ip} in SG {sg_id}")
        return True
    except ec2_client.exceptions.ClientError as e:
        # InvalidPermission.Duplicate = already blocked, treat as success
        if "InvalidPermission.Duplicate" in str(e):
            logger.info(f"SOAR: IP {ip} already blocked")
            return True
        logger.error(f"SOAR: Failed to block {ip}: {e}")
        return False
    except Exception as e:
        logger.error(f"SOAR: Unexpected error blocking {ip}: {e}")
        return False


def unblock_ip(ec2_client, sg_id: str, ip: str) -> bool:
    """Remove deny rule for an IP (manual remediation helper)."""
    try:
        ec2_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": f"{ip}/32"}]
            }]
        )
        logger.info(f"SOAR: Unblocked IP {ip}")
        return True
    except Exception as e:
        logger.error(f"SOAR: Failed to unblock {ip}: {e}")
        return False


def run_soar(job_id: str, report: str, severity: str) -> dict:
    """
    Main SOAR entry point.
    Extracts attacking IPs from report and blocks them in AWS SG.
    Only runs when severity is CRITICAL.
    Returns dict with blocked_ips, skipped_ips, errors.
    """
    result = {
        "soar_triggered": False,
        "blocked_ips":    [],
        "skipped_ips":    [],
        "errors":         [],
    }

    if severity != "CRITICAL":
        logger.info(f"SOAR: Severity {severity} — skipping (only triggers on CRITICAL)")
        return result

    try:
        import boto3
        ec2 = boto3.client("ec2", region_name=AWS_REGION)
    except ImportError:
        result["errors"].append("boto3 not installed")
        logger.error("SOAR: boto3 not installed")
        return result
    except Exception as e:
        result["errors"].append(str(e))
        logger.error(f"SOAR: boto3 init failed: {e}")
        return result

    sg_id = _get_sg_id(ec2, SG_NAME)
    if not sg_id:
        result["errors"].append(f"Security group '{SG_NAME}' not found")
        return result

    ips = _extract_ips(report)
    if not ips:
        logger.info(f"SOAR: No public IPs found in report for job {job_id[:8]}")
        return result

    result["soar_triggered"] = True
    logger.warning(f"SOAR: [{job_id[:8]}] Blocking {len(ips)} IPs: {ips}")

    for ip in ips:
        success = block_ip(ec2, sg_id, ip)
        if success:
            result["blocked_ips"].append(ip)
        else:
            result["skipped_ips"].append(ip)

    logger.warning(
        f"SOAR: [{job_id[:8]}] Done — "
        f"blocked={result['blocked_ips']}, "
        f"skipped={result['skipped_ips']}"
    )
    return result