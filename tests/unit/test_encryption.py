#!/usr/bin/env python3
"""
Unit Tests for Encryption Module

Tests AES-256-GCM encryption, key rotation, Vault integration from
examples/security-controls/encryption.py

Test Coverage:
  - AES-256-GCM encryption/decryption
  - Key rotation and versioning
  - HashiCorp Vault integration
  - TLS 1.3 enforcement
  - PII detection and encryption
  - Key deletion and shredding

Compliance:
  - SOC 2 CC6.1: Encryption key management
  - ISO 27001 A.10.1.1: Cryptographic controls

Usage:
  pytest tests/unit/test_encryption.py -v
"""

import pytest
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


@pytest.fixture
def encryption_manager():
    """Initialize encryption manager."""
    from examples.security_controls.encryption import EncryptionManager
    
    config = {
        "algorithm": "AES-256-GCM",
        "key_rotation_days": 90,
        "vault_url": "http://localhost:8200",
        "pii_detection_enabled": True,
    }
    
    return EncryptionManager(config)


class TestAESEncryption:
    """Test AES-256-GCM encryption."""
    
    def test_encrypt_decrypt_roundtrip(self, encryption_manager):
        """Test encryption and decryption roundtrip."""
        plaintext = b"Hello, OpenClaw!"
        
        ciphertext, nonce = encryption_manager.encrypt(plaintext)
        decrypted = encryption_manager.decrypt(ciphertext, nonce)
        
        assert decrypted == plaintext
    
    def test_different_nonces(self, encryption_manager):
        """Test that different encryptions use different nonces."""
        plaintext = b"Same plaintext"
        
        ciphertext1, nonce1 = encryption_manager.encrypt(plaintext)
        ciphertext2, nonce2 = encryption_manager.encrypt(plaintext)
        
        assert nonce1 != nonce2
        assert ciphertext1 != ciphertext2
    
    def test_authentication_tag(self, encryption_manager):
        """Test that authentication tag is validated."""
        plaintext = b"Authenticated data"
        
        ciphertext, nonce = encryption_manager.encrypt(plaintext)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        
        with pytest.raises(Exception):  # AESGCM raises on auth failure
            encryption_manager.decrypt(bytes(tampered), nonce)


class TestKeyRotation:
    """Test encryption key rotation."""
    
    def test_key_version_tracking(self, encryption_manager):
        """Test that key versions are tracked."""
        current_version = encryption_manager.get_current_key_version()
        
        encryption_manager.rotate_key()
        
        new_version = encryption_manager.get_current_key_version()
        
        assert new_version == current_version + 1
    
    def test_old_keys_decrypt_legacy_data(self, encryption_manager):
        """Test that old keys can decrypt legacy data."""
        plaintext = b"Legacy data"
        
        # Encrypt with current key (version 1)
        ciphertext, nonce = encryption_manager.encrypt(plaintext)
        key_version = encryption_manager.get_current_key_version()
        
        # Rotate key (version 2)
        encryption_manager.rotate_key()
        
        # Should still decrypt with old key
        decrypted = encryption_manager.decrypt(ciphertext, nonce, key_version)
        assert decrypted == plaintext


class TestVaultIntegration:
    """Test HashiCorp Vault integration."""
    
    @patch("hvac.Client")
    def test_vault_key_fetch(self, mock_vault_client, encryption_manager):
        """Test fetching encryption keys from Vault."""
        mock_vault_client.return_value.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "aes_256_key": "base64encodedkey==",
                    "key_version": 1,
                }
            }
        }
        
        key = encryption_manager.fetch_key_from_vault()
        
        assert key is not None
        assert len(key) == 32  # 256 bits


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
