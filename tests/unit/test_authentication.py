#!/usr/bin/env python3  # FIX: C5-finding-4
from __future__ import annotations  # FIX: C5-finding-4

import importlib.util  # FIX: C5-finding-4
import sys  # FIX: C5-finding-4
from pathlib import Path  # FIX: C5-finding-4
from unittest.mock import patch  # FIX: C5-finding-4

import pytest  # FIX: C5-finding-4


AUTHENTICATION_PATH = Path(__file__).resolve().parents[2] / "examples" / "security-controls" / "authentication.py"  # FIX: C5-finding-4


@pytest.fixture(scope="module")  # FIX: C5-finding-4
def authentication_module():  # FIX: C5-finding-4
    spec = importlib.util.spec_from_file_location("openclaw_authentication_issue_7_tests", AUTHENTICATION_PATH)  # FIX: C5-finding-4
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-4
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-4
    sys.modules[spec.name] = module  # FIX: C5-finding-4
    spec.loader.exec_module(module)  # FIX: C5-finding-4
    return module  # FIX: C5-finding-4


def test_password_hasher_round_trip(authentication_module):  # FIX: C5-finding-4
    hashed_password = authentication_module.PasswordHasher.hash_password("ExamplePassword123!")  # FIX: C5-finding-4
    assert hashed_password != "ExamplePassword123!"  # FIX: C5-finding-4
    assert authentication_module.PasswordHasher.verify_password("ExamplePassword123!", hashed_password) is True  # FIX: C5-finding-4
    assert authentication_module.PasswordHasher.verify_password("WrongPassword123!", hashed_password) is False  # FIX: C5-finding-4


def test_password_strength_returns_expected_violations(authentication_module):  # FIX: C5-finding-4
    is_strong, violations = authentication_module.PasswordHasher.validate_password_strength("password")  # FIX: C5-finding-4
    assert is_strong is False  # FIX: C5-finding-4
    assert "Password must be at least 12 characters" in violations  # FIX: C5-finding-4
    assert "Password must contain at least three character classes" in violations  # FIX: C5-finding-4
    assert "Password is too common" in violations  # FIX: C5-finding-4


def test_jwt_manager_returns_payload_for_valid_signed_token(authentication_module):  # FIX: C5-finding-4
    manager = authentication_module.JWTManager("unit-test-secret")  # FIX: C5-finding-4
    with patch.object(authentication_module.time, "time", return_value=1_700_000_000):  # FIX: C5-finding-4
        token = manager.create_access_token("user-123", ["analyst"], expires_in_minutes=15)  # FIX: C5-finding-4
    with patch.object(authentication_module.time, "time", return_value=1_700_000_300):  # FIX: C5-finding-4
        payload = manager.verify_token(token)  # FIX: C5-finding-4
    assert payload == {"sub": "user-123", "roles": ["analyst"], "iat": 1700000000, "exp": 1700000900}  # FIX: C5-finding-4


def test_jwt_manager_rejects_tampered_and_expired_tokens(authentication_module):  # FIX: C5-finding-4
    manager = authentication_module.JWTManager("unit-test-secret")  # FIX: C5-finding-4
    with patch.object(authentication_module.time, "time", return_value=1_700_000_000):  # FIX: C5-finding-4
        token = manager.create_access_token("user-456", ["user"], expires_in_minutes=1)  # FIX: C5-finding-4
    token_body, _signature = token.rsplit(".", 1)  # FIX: C5-finding-4
    tampered_token = f"{token_body}.{'0' * 64}"  # FIX: C5-finding-4
    with patch.object(authentication_module.time, "time", return_value=1_700_000_010):  # FIX: C5-finding-4
        assert manager.verify_token(tampered_token) is None  # FIX: C5-finding-4
    with patch.object(authentication_module.time, "time", return_value=1_700_000_061):  # FIX: C5-finding-4
        assert manager.verify_token(token) is None  # FIX: C5-finding-4


def test_rbac_manager_enforces_role_permissions(authentication_module):  # FIX: C5-finding-4
    permission = authentication_module.Permission  # FIX: C5-finding-4
    rbac_manager = authentication_module.RBACManager  # FIX: C5-finding-4
    assert rbac_manager.has_permission(["admin"], permission.AGENTS_DELETE) is True  # FIX: C5-finding-4
    assert rbac_manager.has_permission(["analyst"], permission.AUDIT_LOGS_READ) is True  # FIX: C5-finding-4
    assert rbac_manager.has_permission(["user"], permission.AGENTS_DELETE) is False  # FIX: C5-finding-4


def test_rbac_manager_accepts_single_role_string(authentication_module):  # FIX: C5-finding-4
    permission = authentication_module.Permission  # FIX: C5-finding-4
    rbac_manager = authentication_module.RBACManager  # FIX: C5-finding-4
    assert rbac_manager.has_permission("admin", permission.AGENTS_DELETE) is True  # FIX: C5-finding-4
    assert rbac_manager.has_permission("user", permission.AGENTS_DELETE) is False  # FIX: C5-finding-4