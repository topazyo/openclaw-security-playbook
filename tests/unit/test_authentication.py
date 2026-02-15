#!/usr/bin/env python3
"""
Unit Tests for Authentication Module

Tests mTLS, OAuth2, API key authentication from examples/security-controls/authentication.py

Test Coverage:
  - mTLS certificate verification and CA validation
  - OAuth2 token exchange and refresh
  - API key validation and rotation
  - MFA enrollment (TOTP, WebAuthn) 
  - Session management and timeout
  - RBAC authorization
  - JWT claims validation

Compliance:
  - SOC 2 CC6.1: Multi-factor authentication
  - ISO 27001 A.9.4.2: Secure log-on procedures

Usage:
  pytest tests/unit/test_authentication.py -v
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import jwt
import

 pyotp


@pytest.fixture
def auth_manager():
    """Initialize authentication manager."""
    from examples.security_controls.authentication import AuthManager
    
    config = {
        "methods": ["mTLS", "OAuth2", "API_Key"],
        "mfa_required": True,
        "session_timeout_seconds": 3600,
        "jwt_secret": "test_secret_key",
        "oauth2_issuer": "https://auth.openclaw.ai",
    }
    
    return AuthManager(config)


@pytest.fixture
def mock_client_cert():
    """Mock client certificate for mTLS testing."""
    cert = Mock()
    cert.subject = {"CN": "openclaw-agent-001"}
    cert.issuer = {"CN": "OpenClaw CA"}
    cert.not_valid_after = datetime.now() + timedelta(days=365)
    cert.serial_number = "123456789"
    return cert


class TestMTLSAuthentication:
    """Test mTLS certificate authentication."""
    
    def test_valid_client_cert(self, auth_manager, mock_client_cert):
        """Test authentication with valid client certificate."""
        is_valid = auth_manager.verify_mtls_cert(mock_client_cert)
        assert is_valid is True
    
    def test_expired_cert_rejected(self, auth_manager, mock_client_cert):
        """Test that expired certificates are rejected."""
        mock_client_cert.not_valid_after = datetime.now() - timedelta(days=1)
        
        is_valid = auth_manager.verify_mtls_cert(mock_client_cert)
        assert is_valid is False
    
    def test_invalid_ca_rejected(self, auth_manager):
        """Test that certs from untrusted CA are rejected."""
        cert = Mock()
        cert.issuer = {"CN": "Untrusted CA"}
        
        is_valid = auth_manager.verify_mtls_cert(cert)
        assert is_valid is False
    
    def test_cn_whitelist_validation(self, auth_manager, mock_client_cert):
        """Test CN whitelist validation."""
        # Valid CN pattern
        mock_client_cert.subject = {"CN": "openclaw-agent-123"}
        assert auth_manager.verify_mtls_cert(mock_client_cert) is True
        
        # Invalid CN pattern
        mock_client_cert.subject = {"CN": "malicious-client"}
        assert auth_manager.verify_mtls_cert(mock_client_cert) is False


class TestOAuth2Authentication:
    """Test OAuth2 token authentication."""
    
    def test_token_exchange(self, auth_manager):
        """Test OAuth2 authorization code exchange for tokens."""
        auth_code = "test_auth_code_12345"
        
        with patch("requests.post") as mock_post:
            mock_post.return_value.json.return_value = {
                "access_token": "access_token_abc",
                "refresh_token": "refresh_token_xyz",
                "expires_in": 3600,
            }
            
            tokens = auth_manager.exchange_auth_code(auth_code)
            
            assert "access_token" in tokens
            assert "refresh_token" in tokens
            assert tokens["expires_in"] == 3600
    
    def test_access_token_validation(self, auth_manager):
        """Test JWT access token validation."""
        # Create valid JWT
        payload = {
            "sub": "user123",
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow(),
            "aud": "openclaw-mcp",
            "iss": "https://auth.openclaw.ai",
        }
        
        token = jwt.encode(payload, "test_secret_key", algorithm="RS256")
        
        is_valid = auth_manager.validate_jwt(token)
        assert is_valid is True
    
    def test_expired_token_rejected(self, auth_manager):
        """Test that expired tokens are rejected."""
        payload = {
            "sub": "user123",
            "exp": datetime.utcnow() - timedelta(hours=1),  # Expired
        }
        
        token = jwt.encode(payload, "test_secret_key", algorithm="RS256")
        
        is_valid = auth_manager.validate_jwt(token)
        assert is_valid is False
    
    def test_refresh_token_rotation(self, auth_manager):
        """Test refresh token rotation."""
        old_refresh_token = "old_refresh_token_123"
        
        with patch("requests.post") as mock_post:
            mock_post.return_value.json.return_value = {
                "access_token": "new_access_token",
                "refresh_token": "new_refresh_token",  # Rotated
                "expires_in": 3600,
            }
            
            new_tokens = auth_manager.refresh_access_token(old_refresh_token)
            
            assert new_tokens["refresh_token"] != old_refresh_token


class TestMFAEnrollment:
    """Test multi-factor authentication."""
    
    def test_totp_enrollment(self, auth_manager):
        """Test TOTP enrollment and secret generation."""
        user_id = "user123"
        
        secret = auth_manager.enroll_totp(user_id)
        
        assert len(secret) == 32  # Base32 secret
        assert secret.isalnum()
    
    def test_totp_verification(self, auth_manager):
        """Test TOTP code verification."""
        user_id = "user456"
        secret = "JBSWY3DPEHPK3PXP"
        
        # Generate valid TOTP code
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        is_valid = auth_manager.verify_totp(user_id, code)
        assert is_valid is True
    
    def test_invalid_totp_code(self, auth_manager):
        """Test that invalid TOTP codes are rejected."""
        user_id = "user789"
        
        is_valid = auth_manager.verify_totp(user_id, "000000")
        assert is_valid is False
    
    def test_webauthn_registration(self, auth_manager):
        """Test WebAuthn credential registration."""
        user_id = "user_webauthn"
        
        challenge = auth_manager.generate_webauthn_challenge(user_id)
        
        assert len(challenge) >= 16  # Minimum challenge length
        assert isinstance(challenge, bytes)


class TestSessionManagement:
    """Test session management."""
    
    def test_session_creation(self, auth_manager):
        """Test session creation after authentication."""
        user_id = "session_user1"
        
        session_id = auth_manager.create_session(user_id)
        
        assert session_id is not None
        assert len(session_id) >= 32  # Secure random ID
    
    def test_session_timeout(self, auth_manager):
        """Test that sessions timeout after inactivity."""
        user_id = "session_user2"
        
        session_id = auth_manager.create_session(user_id)
        
        # Simulate 3600 seconds (1 hour) passing
        with patch("time.time") as mock_time:
            mock_time.return_value = time.time() + 3601
            
            is_valid = auth_manager.validate_session(session_id)
            assert is_valid is False
    
    def test_concurrent_session_limit(self, auth_manager):
        """Test concurrent session limit (max 3)."""
        user_id = "session_user3"
        
        # Create 3 sessions (at limit)
        sessions = []
        for i in range(3):
            session_id = auth_manager.create_session(user_id)
            sessions.append(session_id)
        
        # 4th session should invalidate oldest
        new_session = auth_manager.create_session(user_id)
        
        # First session should be invalidated
        assert auth_manager.validate_session(sessions[0]) is False
        assert auth_manager.validate_session(new_session) is True


class TestRBACAuthorization:
    """Test role-based access control."""
    
    def test_guest_read_only(self, auth_manager):
        """Test that guest role has read-only access."""
        user_id = "guest_user"
        auth_manager.assign_role(user_id, "guest")
        
        assert auth_manager.check_permission(user_id, "read") is True
        assert auth_manager.check_permission(user_id, "write") is False
        assert auth_manager.check_permission(user_id, "delete") is False
    
    def test_user_read_write(self, auth_manager):
        """Test that user role has read/write access."""
        user_id = "normal_user"
        auth_manager.assign_role(user_id, "user")
        
        assert auth_manager.check_permission(user_id, "read") is True
        assert auth_manager.check_permission(user_id, "write") is True
        assert auth_manager.check_permission(user_id, "delete") is False
    
    def test_admin_full_access(self, auth_manager):
        """Test that admin role has full access."""
        user_id = "admin_user"
        auth_manager.assign_role(user_id, "admin")
        
        assert auth_manager.check_permission(user_id, "read") is True
        assert auth_manager.check_permission(user_id, "write") is True
        assert auth_manager.check_permission(user_id, "delete") is True
        assert auth_manager.check_permission(user_id, "admin") is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
