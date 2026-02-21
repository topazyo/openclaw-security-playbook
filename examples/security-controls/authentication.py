# Authentication and Authorization Examples

**Purpose**: Implement secure authentication (AuthN) and authorization (AuthZ) for OpenClaw/ClawdBot APIs, skills, and MCP servers.

**Language**: Python 3.11+  
**Dependencies**: `pyjwt`, `bcrypt`, `cryptography`  
**Last Updated**: 2026-02-14

---

## Table of Contents

1. [Overview](#overview)
2. [Password Authentication](#password-authentication)
3. [API Key Authentication](#api-key-authentication)
4. [JWT Token Authentication](#jwt-token-authentication)
5. [Mutual TLS (mTLS)](#mutual-tls-mtls)
6. [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
7. [Integration Examples](#integration-examples)

---

## Overview

### Authentication vs Authorization

| Concept | Question | Example |
|---------|----------|---------|
| **Authentication (AuthN)** | "Who are you?" | Username/password, API keys, certificates |
| **Authorization (AuthZ)** | "What can you do?" | Roles, permissions, resource access rules |

### Security Principles

1. **Defense in Depth**: Multiple authentication layers
2. **Least Privilege**: Grant minimum required permissions
3. **Zero Trust**: Verify every request, never trust implicitly
4. **Secure by Default**: Deny access unless explicitly granted
5. **Audit Everything**: Log all authentication attempts

**References**:
- [Access Control Policy](../../docs/policies/access-control-policy.md) (SEC-002)
- [Credential Isolation Guide](../../docs/guides/02-credential-isolation.md) (Layer 1)

---

## Password Authentication

### 1. Secure Password Hashing

```python
import bcrypt
import hashlib
import secrets
from typing import Tuple

class PasswordHasher:
    """
    Secure password hashing using bcrypt.
    
    bcrypt is specifically designed for password hashing:
    - Adaptive cost factor (slows down brute force)
    - Built-in salt (prevents rainbow tables)
    - Resistant to timing attacks
    
    References:
    - OWASP Password Storage Cheat Sheet
    - NIST SP 800-63B Digital Identity Guidelines
    """
    
    # Cost factor (work factor)
    # Higher = more secure but slower
    # 12 = ~300ms per hash (as of 2026)
    COST_FACTOR = 12
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Hash password using bcrypt.
        
        Args:
            password: Plaintext password
            
        Returns:
            Hashed password (base64 encoded)
        """
        # Convert to bytes
        password_bytes = password.encode('utf-8')
        
        # Generate salt and hash
        salt = bcrypt.gensalt(rounds=cls.COST_FACTOR)
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        # Return as string
        return hashed.decode('utf-8')
    
    @classmethod
    def verify_password(cls, password: str, hashed: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Plaintext password to verify
            hashed: Previously hashed password
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            password_bytes = password.encode('utf-8')
            hashed_bytes = hashed.encode('utf-8')
            
            # bcrypt.checkpw is resistant to timing attacks
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        except Exception:
            return False
    
    @classmethod
    def validate_password_strength(cls, password: str) -> Tuple[bool, list]:
        """
        Validate password meets strength requirements.
        
        Requirements (NIST 800-63B):
        - Minimum 12 characters
        - No common passwords
        - Not breached (check against HaveIBeenPwned)
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list of violations)
        """
        violations = []
        
        # Length check
        if len(password) < 12:
            violations.append("Password must be at least 12 characters")
        
        # Character diversity (at least 3 of 4 types)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        diversity_count = sum([has_lower, has_upper, has_digit, has_special])
        if diversity_count < 3:
            violations.append("Password must contain at least 3 of: lowercase, uppercase, digits, special characters")
        
        # Common password check (simplified - use real API in production)
        common_passwords = {'password', 'password123', '12345678', 'qwerty', 'abc123'}
        if password.lower() in common_passwords:
            violations.append("Password is too common")
        
        # HaveIBeenPwned check (using k-anonymity)
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        hash_prefix = sha1_hash[:5]
        # In production, check against https://api.pwnedpasswords.com/range/{prefix}
        # For now, skip actual API call
        
        is_valid = len(violations) == 0
        return is_valid, violations


# Usage example
hasher = PasswordHasher()

# Hash password
password = os.environ.get("AUTH_DEMO_PASSWORD", "ExamplePasswordFromEnv123!")
is_strong, violations = hasher.validate_password_strength(password)
if is_strong:
    hashed = hasher.hash_password(password)
    print(f"Hashed: {hashed}")
    
    # Verify correct password
    assert hasher.verify_password(password, hashed)
    print("✓ Password verification succeeded")
    
    # Verify incorrect password
    assert not hasher.verify_password("WrongPassword", hashed)
    print("✓ Wrong password rejected")
else:
    print(f"❌ Weak password: {violations}")
```

### 2. Multi-Factor Authentication (MFA)

```python
import pyotp
import qrcode
from io import BytesIO

class MFAManager:
    """
    TOTP-based Multi-Factor Authentication.
    
    Uses Time-based One-Time Passwords (RFC 6238).
    Compatible with Google Authenticator, Authy, 1Password, etc.
    """
    
    @staticmethod
    def generate_secret() -> str:
        """
        Generate MFA secret for user.
        
        Returns:
            Base32-encoded secret
        """
        return pyotp.random_base32()
    
    @staticmethod
    def get_provisioning_uri(secret: str, user_email: str, issuer: str = "OpenClaw") -> str:
        """
        Generate provisioning URI for QR code.
        
        Args:
            secret: User's MFA secret
            user_email: User's email
            issuer: Service name
            
        Returns:
            otpauth:// URI for QR code
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=user_email, issuer_name=issuer)
    
    @staticmethod
    def generate_qr_code(uri: str) -> BytesIO:
        """
        Generate QR code image for provisioning.
        
        Args:
            uri: Provisioning URI
            
        Returns:
            QR code image as BytesIO
        """
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        return buffer
    
    @staticmethod
    def verify_token(secret: str, token: str) -> bool:
        """
        Verify TOTP token.
        
        Args:
            secret: User's MFA secret
            token: 6-digit token from authenticator app
            
        Returns:
            True if token is valid, False otherwise
        """
        totp = pyotp.TOTP(secret)
        # Allow 1 time step tolerance (60 seconds window)
        return totp.verify(token, valid_window=1)


# Usage example
mfa = MFAManager()

# Setup MFA for user
secret = mfa.generate_secret()
print(f"Secret: {secret}")

uri = mfa.get_provisioning_uri(secret, "alice@openclaw.ai")
print(f"URI: {uri}")

# Generate QR code (user scans with authenticator app)
qr_image = mfa.generate_qr_code(uri)

# Verify token
current_token = pyotp.TOTP(secret).now()
assert mfa.verify_token(secret, current_token)
print(f"✓ Token {current_token} verified")
```

---

## API Key Authentication

### 3. Secure API Key Generation & Storage

```python
import secrets
import hashlib
from typing import Tuple, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class APIKey:
    """API key metadata."""
    key_id: str
    key_hash: str
    name: str
    user_id: str
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    permissions: list


class APIKeyManager:
    """
    Secure API key management.
    
    Security features:
    - Cryptographically secure random generation
    - One-way hashing (never store plaintext)
    - Key rotation and expiration
    - Usage tracking
    
    References:
    - docs/guides/02-credential-isolation.md (API key management)
    - SEC-002 Access Control Policy
    """
    
    PREFIX = "sk-openclaw-"
    KEY_LENGTH = 48  # 288 bits of entropy
    
    @classmethod
    def generate_key(
        cls,
        user_id: str,
        name: str,
        permissions: list,
        expires_in_days: Optional[int] = 90
    ) -> Tuple[str, APIKey]:
        """
        Generate new API key.
        
        Args:
            user_id: Owner user ID
            name: Key description
            permissions: List of permissions
            expires_in_days: Days until expiration (None = no expiration)
            
        Returns:
            Tuple of (plaintext_key, APIKey metadata)
        """
        # Generate cryptographically secure random key
        random_bytes = secrets.token_bytes(cls.KEY_LENGTH)
        key_suffix = secrets.token_urlsafe(cls.KEY_LENGTH)
        
        # Format: sk-openclaw-{random_suffix}
        plaintext_key = f"{cls.PREFIX}{key_suffix}"
        
        # Hash key for storage (NEVER store plaintext)
        key_hash = hashlib.sha256(plaintext_key.encode('utf-8')).hexdigest()
        
        # Generate key ID (for lookup)
        key_id = secrets.token_urlsafe(16)
        
        # Calculate expiration
        created_at = datetime.utcnow()
        expires_at = created_at + timedelta(days=expires_in_days) if expires_in_days else None
        
        # Create metadata
        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            user_id=user_id,
            created_at=created_at,
            expires_at=expires_at,
            last_used_at=None,
            permissions=permissions
        )
        
        return plaintext_key, api_key
    
    @classmethod
    def verify_key(cls, plaintext_key: str, stored_key: APIKey) -> bool:
        """
        Verify API key.
        
        Args:
            plaintext_key: Key from request
            stored_key: Stored key metadata
            
        Returns:
            True if valid, False otherwise
        """
        # Check prefix
        if not plaintext_key.startswith(cls.PREFIX):
            return False
        
        # Check expiration
        if stored_key.expires_at and datetime.utcnow() > stored_key.expires_at:
            return False
        
        # Verify hash
        key_hash = hashlib.sha256(plaintext_key.encode('utf-8')).hexdigest()
        return secrets.compare_digest(key_hash, stored_key.key_hash)
    
    @classmethod
    def rotate_key(cls, old_key: APIKey) -> Tuple[str, APIKey]:
        """
        Rotate API key (generate new, deprecate old).
        
        Args:
            old_key: Existing key to rotate
            
        Returns:
            Tuple of (new_plaintext_key, new_APIKey)
        """
        # Generate new key with same permissions
        return cls.generate_key(
            user_id=old_key.user_id,
            name=f"{old_key.name} (rotated)",
            permissions=old_key.permissions,
            expires_in_days=90
        )


# Usage example
manager = APIKeyManager()

# Generate API key for user
plaintext_key, key_metadata = manager.generate_key(
    user_id="user_alice_123",
    name="Production API Key",
    permissions=["conversations:read", "conversations:write", "agents:read"]
)

print(f"Generated API key: {plaintext_key}")
print(f"Key ID: {key_metadata.key_id}")
print(f"Expires: {key_metadata.expires_at}")

# WARNING: Show key only once, then discard plaintext
# Store only key_metadata (with hash) in database

# Later: Verify incoming API key
is_valid = manager.verify_key(plaintext_key, key_metadata)
print(f"✓ Key verification: {is_valid}")

# Rotation (after 90 days or compromise)
new_key, new_metadata = manager.rotate_key(key_metadata)
print(f"New API key: {new_key}")
```

---

## JWT Token Authentication

### 4. JSON Web Tokens (JWT)

```python
import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional

class JWTManager:
    """
    JWT token management for session authentication.
    
    JWTs are signed tokens containing user claims.
    Used for stateless authentication in distributed systems.
    
    Security considerations:
    - Short expiration (15-60 minutes)
    - Strong signing key (256-bit minimum)
    - Refresh token rotation
    - Token revocation list (for critical cases)
    
    References:
    - RFC 7519: JSON Web Token (JWT)
    - OWASP JWT Cheat Sheet
    """
    
    ALGORITHM = "HS256"  # HMAC-SHA256 (symmetric)
    # In production, use RS256 (asymmetric) for better security
    
    def __init__(self, secret_key: str):
        """
        Initialize JWT manager.
        
        Args:
            secret_key: Secret key for signing (256-bit minimum)
        """
        if len(secret_key) < 32:
            raise ValueError("Secret key must be at least 256 bits (32 bytes)")
        
        self.secret_key = secret_key
    
    def create_access_token(
        self,
        user_id: str,
        roles: list,
        expires_in_minutes: int = 15
    ) -> str:
        """
        Create access token.
        
        Args:
            user_id: User identifier
            roles: User roles
            expires_in_minutes: Token lifetime
            
        Returns:
            JWT token string
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=expires_in_minutes)
        
        payload = {
            'sub': user_id,  # Subject (user ID)
            'iat': now,  # Issued at
            'exp': expires_at,  # Expiration
            'roles': roles,  # User roles
            'type': 'access'  # Token type
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.ALGORITHM)
        return token
    
    def create_refresh_token(
        self,
        user_id: str,
        expires_in_days: int =7
    ) -> str:
        """
        Create refresh token.
        
        Refresh tokens are long-lived tokens used to obtain new access tokens.
        
        Args:
            user_id: User identifier
            expires_in_days: Token lifetime
            
        Returns:
            JWT refresh token
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(days=expires_in_days)
        
        payload = {
            'sub': user_id,
            'iat': now,
            'exp': expires_at,
            'type': 'refresh'
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.ALGORITHM)
        return token
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.ALGORITHM],
                options={'verify_exp': True}  # Verify expiration
            )
            return payload
        except jwt.ExpiredSignatureError:
            # Token expired
            return None
        except jwt.InvalidTokenError:
            # Invalid token
            return None


# Usage example
import secrets

secret_key = secrets.token_urlsafe(32)  # 256-bit key
jwt_manager = JWTManager(secret_key)

# User logs in successfully
user_id = "user_alice_123"
roles = ["user", "agent_operator"]

# Create tokens
access_token = jwt_manager.create_access_token(user_id, roles, expires_in_minutes=15)
refresh_token = jwt_manager.create_refresh_token(user_id, expires_in_days=7)

print(f"Access token: {access_token[:50]}...")
print(f"Refresh token: {refresh_token[:50]}...")

# Later: Verify token on each request
payload = jwt_manager.verify_token(access_token)
if payload:
    print(f"✓ Token valid for user: {payload['sub']}")
    print(f"  Roles: {payload['roles']}")
else:
    print("❌ Token invalid or expired")
```

---

## Mutual TLS (mTLS)

### 5. Certificate-Based Authentication

```python
import ssl
from pathlib import Path
from typing import Optional

class MTLSManager:
    """
    Mutual TLS (mTLS) authentication for MCP servers.
    
    mTLS provides strong authentication using X.509 certificates.
    Both client and server authenticate each other.
    
    Use cases:
    - MCP server authentication
    - Service-to-service authentication
    - Zero-trust networking
    
    References:
    - docs/guides/03-network-segmentation.md (MCP server security)
    - Scenario 003: MCP Server Compromise
    """
    
    def __init__(
        self,
        ca_cert_path: str,
        server_cert_path: str,
        server_key_path: str
    ):
        """
        Initialize mTLS manager.
        
        Args:
            ca_cert_path: CA certificate (for validating client certs)
            server_cert_path: Server certificate
            server_key_path: Server private key
        """
        self.ca_cert_path = Path(ca_cert_path)
        self.server_cert_path = Path(server_cert_path)
        self.server_key_path = Path(server_key_path)
        
        # Validate files exist
        for path in [self.ca_cert_path, self.server_cert_path, self.server_key_path]:
            if not path.exists():
                raise FileNotFoundError(f"Certificate file not found: {path}")
    
    def create_server_context(self) -> ssl.SSLContext:
        """
        Create SSL context for mTLS server.
        
        Returns:
            Configured SSLContext requiring client certificates
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load server certificate and key
        context.load_cert_chain(
            certfile=str(self.server_cert_path),
            keyfile=str(self.server_key_path)
        )
        
        # Load CA certificate for client validation
        context.load_verify_locations(cafile=str(self.ca_cert_path))
        
        # Require client certificates
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Use strong ciphers only
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        # Minimum TLS 1.2
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        return context
    
    def create_client_context(
        self,
        client_cert_path: str,
        client_key_path: str
    ) -> ssl.SSLContext:
        """
        Create SSL context for mTLS client.
        
        Args:
            client_cert_path: Client certificate
            client_key_path: Client private key
            
        Returns:
            Configured SSLContext with client certificate
        """
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Load client certificate and key
        context.load_cert_chain(
            certfile=client_cert_path,
            keyfile=client_key_path
        )
        
        # Load CA certificate for server validation
        context.load_verify_locations(cafile=str(self.ca_cert_path))
        
        # Verify server certificate
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        return context
    
    @staticmethod
    def extract_client_identity(ssl_socket: ssl.SSLSocket) -> Optional[Dict]:
        """
        Extract client identity from certificate.
        
        Args:
            ssl_socket: SSL socket with client connection
            
        Returns:
            Dict with client identity or None
        """
        client_cert = ssl_socket.getpeercert()
        if not client_cert:
            return None
        
        # Extract subject and issuer
        subject = dict(x[0] for x in client_cert['subject'])
        issuer = dict(x[0] for x in client_cert['issuer'])
        
        return {
            'common_name': subject.get('commonName'),
            'organization': subject.get('organizationName'),
            'email': subject.get('emailAddress'),
            'issuer': issuer.get('commonName'),
            'serial_number': client_cert.get('serialNumber'),
            'not_before': client_cert.get('notBefore'),
            'not_after': client_cert.get('notAfter')
        }


# Example: MCP Server with mTLS
# (See scripts/hardening/docker/README.md for certificate generation)

"""
# Generate certificates (one-time setup):

# 1. Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=OpenClaw CA"

# 2. Create server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/CN=mcp-server.openclaw.internal"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# 3. Create client certificate
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -subj "/CN=gateway.openclaw.internal"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
"""

# Usage (server side)
mtls = MTLSManager(
    ca_cert_path="/etc/openclaw/certs/ca.crt",
    server_cert_path="/etc/openclaw/certs/server.crt",
    server_key_path="/etc/openclaw/certs/server.key"
)

server_context = mtls.create_server_context()
print("✓ mTLS server context created")

# Usage (client side)
client_context = mtls.create_client_context(
    client_cert_path="/etc/openclaw/certs/client.crt",
    client_key_path="/etc/openclaw/certs/client.key"
)
print("✓ mTLS client context created")
```

---

## Role-Based Access Control (RBAC)

### 6. RBAC Implementation

```python
from enum import Enum
from typing import Set, List, Dict
from dataclasses import dataclass

class Permission(Enum):
    """Permission definitions."""
    # Conversation permissions
    CONVERSATIONS_READ = "conversations:read"
    CONVERSATIONS_WRITE = "conversations:write"
    CONVERSATIONS_DELETE = "conversations:delete"
    
    # Agent permissions
    AGENTS_READ = "agents: read"
    AGENTS_WRITE = "agents:write"
    AGENTS_DELETE = "agents:delete"
    AGENTS_ADMIN = "agents:admin"
    
    # Skill permissions
    SKILLS_READ = "skills:read"
    SKILLS_INSTALL = "skills:install"
    SKILLS_ADMIN = "skills:admin"
    
    # Admin permissions
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    AUDIT_LOGS_READ = "audit_logs:read"


@dataclass
class Role:
    """Role definition."""
    name: str
    permissions: Set[Permission]
    description: str


class RBACManager:
    """
    Role-Based Access Control manager.
    
    Implements RBAC with predefined roles and permissions.
    
    Role hierarchy:
    - Admin: Full access
    - Agent Operator: Manage agents and conversations
    - User: Read-only access to own data
    - Guest: Minimal read-only access
    
    References:
    - SEC-002 Access Control Policy
    - docs/guides/02-credential-isolation.md (Least privilege)
    """
    
    # Define roles
    ROLES: Dict[str, Role] = {
        'admin': Role(
            name='admin',
            permissions={
                Permission.CONVERSATIONS_READ, Permission.CONVERSATIONS_WRITE, Permission.CONVERSATIONS_DELETE,
                Permission.AGENTS_READ, Permission.AGENTS_WRITE, Permission.AGENTS_DELETE, Permission.AGENTS_ADMIN,
                Permission.SKILLS_READ, Permission.SKILLS_INSTALL, Permission.SKILLS_ADMIN,
                Permission.USERS_READ, Permission.USERS_WRITE,
                Permission.AUDIT_LOGS_READ
            },
            description="Full system access"
        ),
        
        'agent_operator': Role(
            name='agent_operator',
            permissions={
                Permission.CONVERSATIONS_READ, Permission.CONVERSATIONS_WRITE,
                Permission.AGENTS_READ, Permission.AGENTS_WRITE,
                Permission.SKILLS_READ
            },
            description="Operate agents and manage conversations"
        ),
        
        'user': Role(
            name='user',
            permissions={
                Permission.CONVERSATIONS_READ, Permission.CONVERSATIONS_WRITE,
                Permission.AGENTS_READ,
                Permission.SKILLS_READ
            },
            description="Standard user access"
        ),
        
        'guest': Role(
            name='guest',
            permissions={
                Permission.CONVERSATIONS_READ,
                Permission.AGENTS_READ
            },
            description="Read-only guest access"
        )
    }
    
    @classmethod
    def has_permission(
        cls,
        user_roles: List[str],
        required_permission: Permission
    ) -> bool:
        """
        Check if user has required permission.
        
        Args:
            user_roles: List of user's role names
            required_permission: Permission to check
            
        Returns:
            True if user has permission, False otherwise
        """
        # Collect all permissions from user's roles
        user_permissions = set()
        for role_name in user_roles:
            if role_name in cls.ROLES:
                role = cls.ROLES[role_name]
                user_permissions.update(role.permissions)
        
        return required_permission in user_permissions
    
    @classmethod
    def get_user_permissions(cls, user_roles: List[str]) -> Set[Permission]:
        """
        Get all permissions for user.
        
        Args:
            user_roles: List of user's role names
            
        Returns:
            Set of all permissions
        """
        permissions = set()
        for role_name in user_roles:
            if role_name in cls.ROLES:
                role = cls.ROLES[role_name]
                permissions.update(role.permissions)
        
        return permissions


# Usage example
rbac = RBACManager()

# User 1: Admin
admin_roles = ['admin']
can_delete_agent = rbac.has_permission(admin_roles, Permission.AGENTS_DELETE)
print(f"Admin can delete agents: {can_delete_agent}")  # True

# User 2: Regular user
user_roles = ['user']
can_delete_agent = rbac.has_permission(user_roles, Permission.AGENTS_DELETE)
print(f"User can delete agents: {can_delete_agent}")  # False

can_read_conversations = rbac.has_permission(user_roles, Permission.CONVERSATIONS_READ)
print(f"User can read conversations: {can_read_conversations}")  # True

# User 3: Guest
guest_roles = ['guest']
can_write = rbac.has_permission(guest_roles, Permission.CONVERSATIONS_WRITE)
print(f"Guest can write conversations: {can_write}")  # False
```

---

## Integration Examples

### 7. Complete Authentication Middleware

```python
from functools import wraps
from flask import Flask, request, jsonify, g

app = Flask(__name__)

# Initialize managers
jwt_manager = JWTManager(secret_key=secrets.token_urlsafe(32))
rbac = RBACManager()

def require_auth(required_permission: Permission = None):
    """
    Authentication decorator.
    
    Args:
        required_permission: Optional permission required
        
    Usage:
        @app.route('/api/agents', methods=['DELETE'])
        @require_auth(Permission.AGENTS_DELETE)
        def delete_agent():
            return {'result': 'deleted'}
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Extract token from Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid Authorization header'}), 401
            
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Verify JWT token
            payload = jwt_manager.verify_token(token)
            if not payload:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            # Extract user info
            user_id = payload['sub']
            user_roles = payload.get('roles', [])
            
            # Store in request context
            g.user_id = user_id
            g.user_roles = user_roles
            
            # Check permission (if required)
            if required_permission:
                if not rbac.has_permission(user_roles, required_permission):
                    return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Call endpoint
            return f(*args, **kwargs)
        
        return wrapped
    return decorator


@app.route('/api/conversations', methods=['GET'])
@require_auth(Permission.CONVERSATIONS_READ)
def list_conversations():
    """List conversations (requires CONVERSATIONS_READ)."""
    user_id = g.user_id
    return jsonify({'conversations': [], 'user_id': user_id})


@app.route('/api/agents', methods=['DELETE'])
@require_auth(Permission.AGENTS_DELETE)
def delete_agent():
    """Delete agent (requires AGENTS_DELETE - admin only)."""
    agent_id = request.args.get('id')
    return jsonify({'result': 'deleted', 'agent_id': agent_id})


if __name__ == '__main__':
    app.run(debug=True)
```

---

## Best Practices

### 1. Never Store Plaintext Passwords/Keys

```python
# ❌ WRONG: Storing plaintext password
user = {'username': 'alice', 'password': 'MyPassword123'}
db.insert(user)

# ✅ CORRECT: Hash before storing
password_hash = hasher.hash_password('MyPassword123')
user = {'username': 'alice', 'password_hash': password_hash}
db.insert(user)
```

### 2. Use Constant-Time Comparison

```python
# ❌ WRONG: Subject to timing attacks
def verify_api_key(provided, stored):
    return provided == stored  # Timing varies by position of mismatch

# ✅ CORRECT: Constant-time comparison
import secrets

def verify_api_key(provided, stored):
    return secrets.compare_digest(provided, stored)  # Constant time
```

### 3. Implement Rate Limiting on Auth Endpoints

```python
# ✅ CORRECT: Rate limit authentication attempts
@app.route('/auth/login', methods=['POST'])
@rate_limit(limit=5, window=300)  # 5 attempts per 5 minutes
def login():
    # ... authentication logic
    pass
```

---

## Testing

```python
import pytest

def test_password_hashing():
    """Test password hashing and verification."""
    hasher = PasswordHasher()
    password = os.environ.get("TEST_AUTH_PASSWORD", "ExampleTestPassword123!")
    
    hashed = hasher.hash_password(password)
    assert hasher.verify_password(password, hashed)
    assert not hasher.verify_password("WrongPassword", hashed)

def test_jwt_expiration():
    """Test JWT token expiration."""
    import time
    
    jwt_mgr = JWTManager(secrets.token_urlsafe(32))
    token = jwt_mgr.create_access_token('user_123', ['user'], expires_in_minutes=0)  # Expires immediately
    
    time.sleep(1)
    payload = jwt_mgr.verify_token(token)
    assert payload is None  # Expired

def test_rbac_permissions():
    """Test RBAC permission checks."""
    rbac = RBACManager()
    
    # Admin has all permissions
    assert rbac.has_permission(['admin'], Permission.AGENTS_DELETE)
    
    # User doesn't have admin permissions
    assert not rbac.has_permission(['user'], Permission.AGENTS_DELETE)
    
    # User has read permissions
    assert rbac.has_permission(['user'], Permission.CONVERSATIONS_READ)

if __name__ == "__main__":
    pytest.main([__file__, '-v'])
```

---

## References

- **RFC 6238**: TOTP: Time-Based One-Time Password Algorithm
- **RFC 7519**: JSON Web Token (JWT)
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **NIST SP 800-63B**: Digital Identity Guidelines (Authentication)
- **[Access Control Policy](../../docs/policies/access-control-policy.md)**: SEC-002
- **[Credential Isolation Guide](../../docs/guides/02-credential-isolation.md)**: Layer 1 defense

---

**Last Updated**: 2026-02-14  
**Maintainer**: OpenClaw Security Team  
**License**: MIT
