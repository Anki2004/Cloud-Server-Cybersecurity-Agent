import sys
import os
import types
import unittest
from unittest.mock import MagicMock, patch

# ── Add project root + app/ to path ──────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "app"))

# ── Stub boto3 so import doesn't fail without AWS creds ──────────────────────
boto3_stub = types.ModuleType("boto3")
sys.modules.setdefault("boto3", boto3_stub)

from soar import (
    _is_private,
    _extract_ips,
    _get_sg_id,
    block_ip,
    unblock_ip,
    run_soar,
)


# ─────────────────────────────────────────────────────────────────────────────
class TestIsPrivate(unittest.TestCase):

    def test_private_ranges(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1", "169.254.1.1"):
            with self.subTest(ip=ip):
                self.assertTrue(_is_private(ip), f"{ip} should be private")

    def test_public_ips(self):
        for ip in ("8.8.8.8", "1.1.1.1", "203.0.113.5", "45.33.32.156"):
            with self.subTest(ip=ip):
                self.assertFalse(_is_private(ip), f"{ip} should be public")


# ─────────────────────────────────────────────────────────────────────────────
class TestExtractIPs(unittest.TestCase):

    def test_extracts_public_ips(self):
        report = "Attack from 45.33.32.156 and also 203.0.113.5"
        ips = _extract_ips(report)
        self.assertIn("45.33.32.156", ips)
        self.assertIn("203.0.113.5", ips)

    def test_excludes_private_ips(self):
        report = "Local 192.168.1.1 and remote 8.8.8.8"
        ips = _extract_ips(report)
        self.assertNotIn("192.168.1.1", ips)
        self.assertIn("8.8.8.8", ips)

    def test_deduplication(self):
        report = "45.33.32.156 attacked again 45.33.32.156 and 45.33.32.156"
        ips = _extract_ips(report)
        self.assertEqual(ips.count("45.33.32.156"), 1)

    def test_no_ips_in_report(self):
        self.assertEqual(_extract_ips("no ip addresses here"), [])

    def test_empty_report(self):
        self.assertEqual(_extract_ips(""), [])


# ─────────────────────────────────────────────────────────────────────────────
class TestGetSgId(unittest.TestCase):

    def test_returns_sg_id_when_found(self):
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-abc123"}]
        }
        result = _get_sg_id(ec2, "my-sg")
        self.assertEqual(result, "sg-abc123")

    def test_returns_none_when_not_found(self):
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        self.assertIsNone(_get_sg_id(ec2, "missing-sg"))

    def test_returns_none_on_exception(self):
        ec2 = MagicMock()
        ec2.describe_security_groups.side_effect = Exception("AWS error")
        self.assertIsNone(_get_sg_id(ec2, "any-sg"))


# ─────────────────────────────────────────────────────────────────────────────
class TestBlockIp(unittest.TestCase):

    def _make_ec2(self):
        ec2 = MagicMock()
        # Make ec2.exceptions.ClientError a real exception subclass
        ec2.exceptions = MagicMock()
        ec2.exceptions.ClientError = type("ClientError", (Exception,), {})
        return ec2

    def test_block_success(self):
        ec2 = self._make_ec2()
        result = block_ip(ec2, "sg-abc123", "45.33.32.156")
        self.assertTrue(result)
        ec2.authorize_security_group_ingress.assert_called_once()

    def test_block_duplicate_treated_as_success(self):
        ec2 = self._make_ec2()
        ec2.authorize_security_group_ingress.side_effect = (
            ec2.exceptions.ClientError("InvalidPermission.Duplicate")
        )
        result = block_ip(ec2, "sg-abc123", "45.33.32.156")
        self.assertTrue(result)

    def test_block_other_client_error_returns_false(self):
        ec2 = self._make_ec2()
        ec2.authorize_security_group_ingress.side_effect = (
            ec2.exceptions.ClientError("SomeOtherError")
        )
        result = block_ip(ec2, "sg-abc123", "45.33.32.156")
        self.assertFalse(result)

    def test_block_unexpected_exception_returns_false(self):
        ec2 = self._make_ec2()
        ec2.authorize_security_group_ingress.side_effect = RuntimeError("boom")
        result = block_ip(ec2, "sg-abc123", "45.33.32.156")
        self.assertFalse(result)


# ─────────────────────────────────────────────────────────────────────────────
class TestUnblockIp(unittest.TestCase):

    def test_unblock_success(self):
        ec2 = MagicMock()
        result = unblock_ip(ec2, "sg-abc123", "45.33.32.156")
        self.assertTrue(result)
        ec2.revoke_security_group_ingress.assert_called_once()

    def test_unblock_failure_returns_false(self):
        ec2 = MagicMock()
        ec2.revoke_security_group_ingress.side_effect = Exception("fail")
        result = unblock_ip(ec2, "sg-abc123", "45.33.32.156")
        self.assertFalse(result)


# ─────────────────────────────────────────────────────────────────────────────
class TestRunSoar(unittest.TestCase):

    REPORT_WITH_PUBLIC_IP = "Brute force from 45.33.32.156 detected"

    def test_skips_if_not_critical(self):
        for sev in ("HIGH", "MEDIUM", "LOW"):
            with self.subTest(severity=sev):
                result = run_soar("job-1", self.REPORT_WITH_PUBLIC_IP, sev)
                self.assertFalse(result["soar_triggered"])
                self.assertEqual(result["blocked_ips"], [])

    def _make_mock_boto3(self):
        """Return (mock_boto3, mock_ec2) with ClientError stubbed."""
        mock_boto3 = MagicMock()
        mock_ec2 = MagicMock()
        mock_ec2.exceptions = MagicMock()
        mock_ec2.exceptions.ClientError = type("ClientError", (Exception,), {})
        mock_boto3.client.return_value = mock_ec2
        return mock_boto3, mock_ec2

    def test_no_ips_found_no_trigger(self):
        mock_boto3, mock_ec2 = self._make_mock_boto3()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-abc123"}]
        }
        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            result = run_soar("job-2", "no ip addresses here", "CRITICAL")
        self.assertFalse(result["soar_triggered"])

    def test_blocks_public_ips_on_critical(self):
        mock_boto3, mock_ec2 = self._make_mock_boto3()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-abc123"}]
        }
        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            result = run_soar("job-3", self.REPORT_WITH_PUBLIC_IP, "CRITICAL")
        self.assertTrue(result["soar_triggered"])
        self.assertIn("45.33.32.156", result["blocked_ips"])

    def test_sg_not_found_no_block(self):
        mock_boto3, mock_ec2 = self._make_mock_boto3()
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            result = run_soar("job-4", self.REPORT_WITH_PUBLIC_IP, "CRITICAL")
        self.assertFalse(result["soar_triggered"])
        self.assertTrue(len(result["errors"]) > 0)

    def test_boto3_import_error_caught(self):
        # None in sys.modules → `import boto3` raises ImportError inside run_soar
        with patch.dict(sys.modules, {"boto3": None}):
            result = run_soar("job-5", self.REPORT_WITH_PUBLIC_IP, "CRITICAL")
        self.assertFalse(result["soar_triggered"])
        self.assertTrue(len(result["errors"]) > 0)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    unittest.main()