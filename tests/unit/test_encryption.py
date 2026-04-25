#!/usr/bin/env python3  # FIX: C5-finding-4
from __future__ import annotations  # FIX: C5-finding-4

import base64  # FIX: C5-finding-4
import importlib.util  # FIX: C5-finding-4
import sys  # FIX: C5-finding-4
from pathlib import Path  # FIX: C5-finding-4
from types import ModuleType, SimpleNamespace  # FIX: C5-finding-4
from unittest.mock import Mock, patch  # FIX: C5-finding-4

import pytest  # FIX: C5-finding-4


ENCRYPTION_PATH = Path(__file__).resolve().parents[2] / "examples" / "security-controls" / "encryption.py"  # FIX: C5-finding-4


@pytest.fixture(scope="module")  # FIX: C5-finding-4
def encryption_module():  # FIX: C5-finding-4
    spec = importlib.util.spec_from_file_location("openclaw_encryption_issue_7_tests", ENCRYPTION_PATH)  # FIX: C5-finding-4
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-4
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-4
    sys.modules[spec.name] = module  # FIX: C5-finding-4
    spec.loader.exec_module(module)  # FIX: C5-finding-4
    return module  # FIX: C5-finding-4


def test_data_encryptor_round_trip(encryption_module):  # FIX: C5-finding-4
    encryptor = encryption_module.DataEncryptor(b"0" * 32)  # FIX: C5-finding-4
    plaintext = b"Hello, OpenClaw!"  # FIX: C5-finding-4
    encrypted = encryptor.encrypt_data(plaintext)  # FIX: C5-finding-4
    assert encrypted != plaintext  # FIX: C5-finding-4
    assert encryptor.decrypt_data(encrypted) == plaintext  # FIX: C5-finding-4


def test_data_encryptor_uses_distinct_nonces(encryption_module):  # FIX: C5-finding-4
    encryptor = encryption_module.DataEncryptor(b"1" * 32)  # FIX: C5-finding-4
    nonce_one = b"\x00" * 12  # FIX: C5-finding-4
    nonce_two = b"\x01" * 12  # FIX: C5-finding-4
    with patch.object(encryption_module.os, "urandom", side_effect=[nonce_one, nonce_two]):  # FIX: C5-finding-4
        encrypted_one = encryptor.encrypt_data(b"same plaintext")  # FIX: C5-finding-4
        encrypted_two = encryptor.encrypt_data(b"same plaintext")  # FIX: C5-finding-4
    assert encrypted_one[:12] == nonce_one  # FIX: C5-finding-4
    assert encrypted_two[:12] == nonce_two  # FIX: C5-finding-4
    assert encrypted_one != encrypted_two  # FIX: C5-finding-4


def test_data_encryptor_detects_tampering(encryption_module):  # FIX: C5-finding-4
    encryptor = encryption_module.DataEncryptor(b"2" * 32)  # FIX: C5-finding-4
    encrypted = bytearray(encryptor.encrypt_data(b"Authenticated data"))  # FIX: C5-finding-4
    encrypted[-1] ^= 0xFF  # FIX: C5-finding-4
    with pytest.raises(encryption_module.InvalidTag):  # FIX: C5-finding-4
        encryptor.decrypt_data(bytes(encrypted))  # FIX: C5-finding-4


def test_derive_key_from_password_is_deterministic_for_same_salt(encryption_module):  # FIX: C5-finding-4
    salt = b"static-salt-value"  # FIX: C5-finding-4
    key_one = encryption_module.derive_key_from_password("user-password-123", salt, iterations=100000)  # FIX: C5-finding-4
    key_two = encryption_module.derive_key_from_password("user-password-123", salt, iterations=100000)  # FIX: C5-finding-4
    key_three = encryption_module.derive_key_from_password("user-password-123", b"other-salt-value", iterations=100000)  # FIX: C5-finding-4
    assert len(key_one) == 32  # FIX: C5-finding-4
    assert key_one == key_two  # FIX: C5-finding-4
    assert key_one != key_three  # FIX: C5-finding-4


def test_derive_key_from_password_rejects_short_salt(encryption_module):  # FIX: C5-finding-4
    with pytest.raises(ValueError, match="at least 16 bytes"):  # FIX: C5-finding-4
        encryption_module.derive_key_from_password("user-password-123", b"short", iterations=100000)  # FIX: C5-finding-4


def test_derive_key_from_password_rejects_low_iteration_count(encryption_module):  # FIX: C5-finding-4
    with pytest.raises(ValueError, match="at least 100000"):  # FIX: C5-finding-4
        encryption_module.derive_key_from_password("user-password-123", b"0123456789abcdef", iterations=1)  # FIX: C5-finding-4


def test_vault_key_manager_creates_keys_and_rotates_versions(encryption_module):  # FIX: C5-finding-4
    fake_client = Mock()  # FIX: C5-finding-4
    fake_client.is_authenticated.return_value = True  # FIX: C5-finding-4
    fake_client.secrets = SimpleNamespace(transit=Mock())  # FIX: C5-finding-4
    fake_client.secrets.transit.read_key.return_value = {"data": {"latest_version": 3}}  # FIX: C5-finding-4
    fake_hvac = ModuleType("hvac")  # FIX: C5-finding-4
    fake_hvac.Client = Mock(return_value=fake_client)  # FIX: C5-finding-4
    with patch.dict(sys.modules, {"hvac": fake_hvac}):  # FIX: C5-finding-4
        manager = encryption_module.VaultKeyManager("http://vault.local", "token")  # FIX: C5-finding-4
        key_name = manager.create_key("openclaw-conversations")  # FIX: C5-finding-4
        version = manager.rotate_key("openclaw-conversations")  # FIX: C5-finding-4
    assert key_name == "openclaw-conversations"  # FIX: C5-finding-4
    fake_client.secrets.transit.create_key.assert_called_once_with(name="openclaw-conversations", exportable=False, key_type="aes256-gcm96")  # FIX: C5-finding-4
    fake_client.secrets.transit.rotate_key.assert_called_once_with(name="openclaw-conversations")  # FIX: C5-finding-4
    assert version == 3  # FIX: C5-finding-4


def test_vault_key_manager_encrypts_and_decrypts_via_transit(encryption_module):  # FIX: C5-finding-4
    fake_client = Mock()  # FIX: C5-finding-4
    fake_client.is_authenticated.return_value = True  # FIX: C5-finding-4
    fake_client.secrets = SimpleNamespace(transit=Mock())  # FIX: C5-finding-4
    fake_client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:encrypted"}}  # FIX: C5-finding-4
    fake_client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": base64.b64encode(b"secret").decode("utf-8")}}  # FIX: C5-finding-4
    fake_hvac = ModuleType("hvac")  # FIX: C5-finding-4
    fake_hvac.Client = Mock(return_value=fake_client)  # FIX: C5-finding-4
    with patch.dict(sys.modules, {"hvac": fake_hvac}):  # FIX: C5-finding-4
        manager = encryption_module.VaultKeyManager("http://vault.local", "token")  # FIX: C5-finding-4
        ciphertext = manager.encrypt_with_vault("openclaw-conversations", b"secret")  # FIX: C5-finding-4
        plaintext = manager.decrypt_with_vault("openclaw-conversations", ciphertext)  # FIX: C5-finding-4
    assert ciphertext == "vault:v1:encrypted"  # FIX: C5-finding-4
    fake_client.secrets.transit.encrypt_data.assert_called_once_with(name="openclaw-conversations", plaintext=base64.b64encode(b"secret").decode("utf-8"))  # FIX: C5-finding-4
    fake_client.secrets.transit.decrypt_data.assert_called_once_with(name="openclaw-conversations", ciphertext="vault:v1:encrypted")  # FIX: C5-finding-4
    assert plaintext == b"secret"  # FIX: C5-finding-4