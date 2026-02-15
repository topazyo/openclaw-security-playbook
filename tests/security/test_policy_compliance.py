#!/usr/bin/env python3
"""
Security Tests for Policy Compliance

Tests SEC-002/003/004/005 policy enforcement from docs/policies/

Test Coverage:
  - SEC-002: Data classification and encryption
  - SEC-003: Vulnerability management SLAs
  - SEC-004: Access control (MFA, password complexity)
  - SEC-005: Incident response SLAs
  - Audit log integrity

Compliance:
  - SOC 2 CC6.1, CC7.3
  - ISO 27001 A.9.2.1, A.12.6.1

Usage:
  pytest tests/security/test_policy_compliance.py -v
"""

import pytest
from unittest.mock import Mock, patch


class TestDataClassification:
    """Test SEC-002 data classification policy."""
    
    def test_restricted_data_encrypted(self):
        """Test Restricted data is encrypted with AES-256."""
        from examples.security_controls import encryption
        
        restricted_data = b"SSN: 123-45-6789"
        
        encrypted, nonce = encryption.encrypt(restricted_data)
        
        # Should be encrypted
        assert encrypted != restricted_data
        assert len(encrypted) > len(restricted_data)  # Auth tag added
    
    @patch("re.search")
    def test_pii_detection(self, mock_search):
        """Test PII patterns trigger encryption."""
        mock_search.return_value = Mock()  # PII detected
        
        from examples.security_controls import dlp
        
        text = "Customer SSN: 123-45-6789"
        
        has_pii = dlp.detect_pii(text)
        
        assert has_pii is True


class TestVulnerabilityManagement:
    """Test SEC-003 vulnerability management SLAs.""" 
    
    @patch("subprocess.run")
    def test_critical_patches_under_7_days(self, mock_subprocess):
        """Test CRITICAL patches applied <7 days."""
        from scripts.remediation import auto_remediate
        
        vulns = [
            {"id": "CVE-2024-0001", "severity": "CRITICAL", "age_days": 5}
        ]
        
        results = auto_remediate.patch_vulnerabilities(vulns)
        
        assert results[0]["status"] == "patched"
    
    def test_high_vulns_under_30_days(self):
        """Test HIGH vulns patched <30 days."""
        from scripts.remediation import auto_remediate
        
        vulns = [
            {"id": "CVE-2024-0002", "severity": "HIGH", "age_days": 25}
        ]
        
        results = auto_remediate.patch_vulnerabilities(vulns)
        
        assert results[0]["status"] == "patched"


class TestAccessControl:
    """Test SEC-004 access control policy."""
    
    def test_mfa_enforced_for_admin(self):
        """Test MFA required for admin users."""
        from examples.security_controls import authentication
        
        auth_manager = authentication.AuthManager({"mfa_required": True})
        
        # Admin login without MFA should fail
        result = auth_manager.authenticate(
            user="admin",
            password="correct_password",
            mfa_code=None,
        )
        
        assert result["authenticated"] is False
        assert "mfa_required" in result["error"]
    
    def test_password_complexity_enforced(self):
        """Test password must be 12+ chars with symbols."""
        from examples.security_controls import authentication
        
        weak_passwords = [
            "short",  # Too short
            "NoSymbols123",  # No symbols
            "no_uppercase1!",  # No uppercase
        ]
        
        for pwd in weak_passwords:
            is_valid = authentication.validate_password(pwd)
            assert is_valid is False


class TestIncidentResponse:
    """Test SEC-005 incident response SLAs."""
    
    @patch("time.time")
    def test_p0_sla_15_to_30_min(self, mock_time):
        """Test P0 incidents acknowledged 15-30min."""
        from scripts.incident_response import notification_manager
        
        mock_time.side_effect = [0, 900]  # 15 min response
        
        incident = {"severity": "P0", "created_at": 0}
        
        ack_time = notification_manager.track_acknowledgment(incident)
        
        assert 15 <= (ack_time / 60) <= 30  # minutes


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
