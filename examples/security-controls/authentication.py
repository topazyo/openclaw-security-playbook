"""Secure authentication examples used by Bandit and compile validation.

This module intentionally stays dependency-light so CI can compile and lint it
without optional third-party packages.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Optional, Tuple


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class PasswordHasher:
    """PBKDF2-HMAC password hashing example with constant-time verification."""

    ITERATIONS = 120_000
    SALT_BYTES = 16

    @classmethod
    def hash_password(cls, password: str) -> str:
        salt = secrets.token_bytes(cls.SALT_BYTES)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, cls.ITERATIONS)
        return base64.b64encode(salt + digest).decode("ascii")

    @classmethod
    def verify_password(cls, password: str, encoded_hash: str) -> bool:
        try:
            decoded = base64.b64decode(encoded_hash.encode("ascii"), validate=True)
        except (ValueError, TypeError):
            return False
        if len(decoded) <= cls.SALT_BYTES:
            return False
        salt = decoded[: cls.SALT_BYTES]
        expected_digest = decoded[cls.SALT_BYTES :]
        actual_digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, cls.ITERATIONS)
        return hmac.compare_digest(actual_digest, expected_digest)

    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, list[str]]:
        violations: list[str] = []
        if len(password) < 12:
            violations.append("Password must be at least 12 characters")
        classes = [
            any(ch.islower() for ch in password),
            any(ch.isupper() for ch in password),
            any(ch.isdigit() for ch in password),
            any(not ch.isalnum() for ch in password),
        ]
        if sum(classes) < 3:
            violations.append("Password must contain at least three character classes")
        common_passwords = {"password", "password123", "12345678", "qwerty", "abc123"}
        if password.lower() in common_passwords:
            violations.append("Password is too common")
        return len(violations) == 0, violations


class Permission(str, Enum):
    CONVERSATIONS_READ = "conversations.read"
    AGENTS_DELETE = "agents.delete"
    AUDIT_LOGS_READ = "audit.read"


class RBACManager:
    """Minimal RBAC example for authorization checks."""

    ROLE_PERMISSIONS: Dict[str, set[Permission]] = {
        "admin": {Permission.CONVERSATIONS_READ, Permission.AGENTS_DELETE, Permission.AUDIT_LOGS_READ},
        "analyst": {Permission.CONVERSATIONS_READ, Permission.AUDIT_LOGS_READ},
        "user": {Permission.CONVERSATIONS_READ},
    }

    @classmethod
    def has_permission(cls, roles: Iterable[str], permission: Permission) -> bool:
        return any(permission in cls.ROLE_PERMISSIONS.get(role, set()) for role in roles)


@dataclass(frozen=True)
class AccessToken:
    subject: str
    roles: tuple[str, ...]
    issued_at: int
    expires_at: int
    nonce: str

    def encode(self) -> str:
        return base64.urlsafe_b64encode(json.dumps(self.__dict__).encode("utf-8")).decode("ascii")

    @classmethod
    def decode(cls, token: str) -> Optional["AccessToken"]:
        try:
            payload = json.loads(base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8"))
        except (ValueError, TypeError, json.JSONDecodeError):
            return None
        try:
            return cls(
                subject=payload["subject"],
                roles=tuple(payload["roles"]),
                issued_at=int(payload["issued_at"]),
                expires_at=int(payload["expires_at"]),
                nonce=str(payload["nonce"]),
            )
        except (KeyError, TypeError, ValueError):
            return None


class JWTManager:
    """Dependency-free signed-token example for CI-friendly usage docs."""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode("utf-8")

    def create_access_token(self, subject: str, roles: list[str], expires_in_minutes: int = 15) -> str:
        issued_at = int(time.time())
        expires_at = issued_at + max(expires_in_minutes, 0) * 60
        token = AccessToken(
            subject=subject,
            roles=tuple(roles),
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=secrets.token_urlsafe(12),
        )
        body = token.encode()
        signature = hmac.new(self.secret_key, body.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{body}.{signature}"

    def verify_token(self, token: str) -> Optional[dict[str, object]]:
        try:
            body, provided_signature = token.rsplit(".", 1)
        except ValueError:
            return None
        expected_signature = hmac.new(self.secret_key, body.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, provided_signature):
            return None
        payload = AccessToken.decode(body)
        if payload is None or payload.expires_at <= int(time.time()):
            return None
        return {
            "sub": payload.subject,
            "roles": list(payload.roles),
            "iat": payload.issued_at,
            "exp": payload.expires_at,
        }


def test_password_hashing() -> None:
    password = os.environ.get("TEST_AUTH_PASSWORD", "ExampleTestPassword123!")
    is_strong, violations = PasswordHasher.validate_password_strength(password)
    ensure(is_strong, f"Expected strong password, got violations: {violations}")
    hashed = PasswordHasher.hash_password(password)
    ensure(PasswordHasher.verify_password(password, hashed), "Password verification should succeed")
    ensure(not PasswordHasher.verify_password("WrongPassword", hashed), "Wrong password should be rejected")


def test_jwt_expiration() -> None:
    jwt_manager = JWTManager(secrets.token_urlsafe(24))
    token = jwt_manager.create_access_token("user-123", ["user"], expires_in_minutes=0)
    ensure(jwt_manager.verify_token(token) is None, "Expired token should not validate")


def test_rbac_permissions() -> None:
    ensure(RBACManager.has_permission(["admin"], Permission.AGENTS_DELETE), "Admin should delete agents")
    ensure(not RBACManager.has_permission(["user"], Permission.AGENTS_DELETE), "User should not delete agents")
    ensure(RBACManager.has_permission(["user"], Permission.CONVERSATIONS_READ), "User should read conversations")


def run_examples() -> None:
    password = os.environ.get("AUTH_DEMO_PASSWORD", "ExamplePasswordFromEnv123!")
    is_strong, violations = PasswordHasher.validate_password_strength(password)
    ensure(is_strong, f"Demo password is too weak: {violations}")
    hashed = PasswordHasher.hash_password(password)
    print("Hashed password created")
    ensure(PasswordHasher.verify_password(password, hashed), "Expected password verification to succeed")
    token_manager = JWTManager(secrets.token_urlsafe(24))
    token = token_manager.create_access_token("analyst-1", ["analyst"])
    ensure(token_manager.verify_token(token) is not None, "Expected token verification to succeed")
    print("Authentication examples completed")


if __name__ == "__main__":
    run_examples()
    test_password_hashing()
    test_jwt_expiration()
    test_rbac_permissions()
