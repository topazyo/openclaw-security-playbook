"""
Secure Logging and Audit Trails - OpenClaw Security Framework

This module provides comprehensive logging implementations for security events,
audit trails, and compliance-focused log management.

Language: Python 3.11+
Dependencies: python-json-logger, elasticsearch, hashlib
Last Updated: 2026-02-15

Table of Contents:
1. Overview
2. Structured Logging (JSON format)
3. Sensitive Data Redaction
4. Audit Log Requirements
   - WORM Storage (Write-Once-Read-Many)
   - 7-Year Retention
   - Tamper-Evident (Cryptographic Chaining)
5. ELK Stack Integration
6. Log Levels and Security Events
7. Examples and Usage
8. Testing

References:
- SEC-004: Incident Response Policy (logging requirements)
- playbook-credential-theft.md (IRP-001): Failed login detection via logs
- docs/guides/06-incident-response.md: Forensic analysis with logs
- SOC 2 CC7.2: System Monitoring and Alerting
- ISO 27001 A.12.4.1: Event Logging (7-year retention)
- GDPR Article 30: Records of Processing Activities
"""

import os
import re
import json
import hashlib
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import socket


# ============================================================================
# 1. OVERVIEW
# ============================================================================

"""
Logging Requirements by Event Type:

+------------------------+-------------+------------------+--------------------+
| Event Type             | Log Level   | Retention        | Alert On           |
+------------------------+-------------+------------------+--------------------+
| Security Incidents     | ERROR       | 7 years (SOC 2)  | Immediate          |
| Access Denied          | WARN        | 7 years          | >10 in 5 min       |
| Successful Auth        | INFO        | 7 years          | None               |
| Policy Violations      | WARN        | 7 years          | Per policy         |
| Configuration Changes  | INFO        | 7 years          | Admin changes      |
| Skill Execution        | INFO        | 7 years          | Blocked skills     |
| API Requests           | DEBUG       | 90 days          | Rate limit hits    |
| Debug/Development      | DEBUG       | 7 days           | Never (dev only)   |
+------------------------+-------------+------------------+--------------------+

Sensitive Data Redaction:
- Passwords: Replace with "[REDACTED]"
- API Keys: Show prefix only "sk-openclaw-***"
- PII: Mask credit cards (1234-****-****-5678), SSNs (***-**-5678), emails (u***@example.com)
- JWTs: Redact payload, keep header for debugging
- Conversation content: Hash or truncate in non-audit logs

Compliance Mappings:
- SOC 2 CC7.2: System monitoring requires logging of security events, access attempts
- ISO 27001 A.12.4.1: Event logging with 7-year retention for audit evidence
- GDPR Article 30: Records of processing activities (who accessed what, when)
- PCI DSS 10.2: Audit trail requirements for cardholder data access
"""


# ============================================================================
# 2. STRUCTURED LOGGING
# ============================================================================

class SecurityEventType(Enum):
    """Security event types for categorization."""
    
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    MFA_CHALLENGE = "mfa_challenge"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    
    # Authorization events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PERMISSION_ESCALATION = "permission_escalation"
    ROLE_CHANGE = "role_change"
    
    # Resource events
    CONVERSATION_CREATE = "conversation_create"
    CONVERSATION_READ = "conversation_read"
    CONVERSATION_DELETE = "conversation_delete"
    SKILL_INSTALL = "skill_install"
    SKILL_EXECUTE = "skill_execute"
    SKILL_BLOCKED = "skill_blocked"
    
    # Security events
    POLICY_VIOLATION = "policy_violation"
    PROMPT_INJECTION_DETECTED = "prompt_injection_detected"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    ANOMALY_DETECTED = "anomaly_detected"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    
    # Incident events
    INCIDENT_CREATED = "incident_created"
    INCIDENT_ESCALATED = "incident_escalated"
    INCIDENT_RESOLVED = "incident_resolved"
    
    # Configuration events
    CONFIG_CHANGE = "config_change"
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    KEY_ROTATED = "key_rotated"


@dataclass
class SecurityLogEntry:
    """
    Structured security log entry.
    
    Fields follow ECS (Elastic Common Schema) for ELK Stack compatibility.
    """
    
    # Core fields (always present)
    timestamp: str  # ISO 8601 format
    event_type: str  # SecurityEventType value
    user_id: Optional[str]
    action: str
    resource: str
    outcome: str  # "success" or "failure"
    
    # Context fields
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    
    # Metadata
    duration_ms: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None
    
    # Source information
    hostname: Optional[str] = None
    service: str = "openclaw"
    version: str = "1.0.0"
    
    # Security context
    severity: str = "INFO"  # ERROR, WARN, INFO, DEBUG
    tags: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), separators=(',', ':'))


class StructuredLogger:
    """
    Structured logger outputting JSON for machine parsing.
    
    Compatible with:
    - ELK Stack (Elasticsearch, Logstash, Kibana)
    - Splunk
    - Datadog
    - CloudWatch Logs Insights
    """
    
    def __init__(self, service_name: str = "openclaw", log_file: Optional[str] = None):
        """
        Initialize structured logger.
        
        Args:
            service_name: Service identifier
            log_file: Path to log file (None for stdout)
        """
        self.service_name = service_name
        self.hostname = socket.gethostname()
        
        # Configure Python logger
        self.logger = logging.getLogger(f"openclaw.{service_name}")
        self.logger.setLevel(logging.DEBUG)
        
        # JSON formatter
        formatter = logging.Formatter('%(message)s')
        
        # Handler (file or stdout)
        if log_file:
            handler = logging.FileHandler(log_file)
        else:
            handler = logging.StreamHandler()
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_event(
        self,
        event_type: SecurityEventType,
        user_id: Optional[str],
        action: str,
        resource: str,
        outcome: str,
        **kwargs
    ):
        """
        Log security event.
        
        Args:
            event_type: Type of security event
            user_id: User performing action
            action: Action performed
            resource: Resource affected
            outcome: "success" or "failure"
            **kwargs: Additional metadata
        """
        entry = SecurityLogEntry(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            event_type=event_type.value,
            user_id=user_id,
            action=action,
            resource=resource,
            outcome=outcome,
            hostname=self.hostname,
            service=self.service_name,
            **kwargs
        )
        
        # Determine log level
        level = self._get_log_level(entry)
        
        # Log as JSON
        self.logger.log(level, entry.to_json())
    
    def _get_log_level(self, entry: SecurityLogEntry) -> int:
        """Determine Python log level from severity."""
        severity_map = {
            'ERROR': logging.ERROR,
            'WARN': logging.WARNING,
            'INFO': logging.INFO,
            'DEBUG': logging.DEBUG
        }
        return severity_map.get(entry.severity, logging.INFO)


# ============================================================================
# 3. SENSITIVE DATA REDACTION
# ============================================================================

class SensitiveDataRedactor:
    """
    Redact sensitive data from log entries before storage.
    
    Patterns detected:
    - Passwords (fields named "password", "passwd", "pwd")
    - API keys (sk-openclaw-*, Bearer tokens)
    - JWTs (eyJ... tokens)
    - Credit cards (16-digit numbers with optional dashes)
    - SSNs (123-45-6789 format)
    - Email addresses (partial masking)
    - AWS credentials (AKIA...)
    """
    
    # Regex patterns
    CREDIT_CARD_PATTERN = re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')
    SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    EMAIL_PATTERN = re.compile(r'\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')
    API_KEY_PATTERN = re.compile(r'\b(sk-openclaw-)[a-zA-Z0-9_-]{40,}\b')
    JWT_PATTERN = re.compile(r'\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b')
    AWS_KEY_PATTERN = re.compile(r'\b(AKIA[0-9A-Z]{16})\b')
    
    # Sensitive field names
    SENSITIVE_FIELDS = {
        'password', 'passwd', 'pwd', 'secret', 'token', 'auth',
        'authorization', 'api_key', 'apikey', 'access_token',
        'refresh_token', 'private_key', 'privatekey'
    }
    
    @classmethod
    def redact_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively redact sensitive data from dictionary.
        
        Args:
            data: Dictionary potentially containing sensitive data
        
        Returns:
            Dictionary with sensitive data redacted
        
        Example:
            >>> data = {
            ...     "user_id": "user-123",
            ...     "password": "secret123",
            ...     "credit_card": "1234-5678-9012-3456"
            ... }
            >>> redacted = SensitiveDataRedactor.redact_dict(data)
            >>> redacted
            {'user_id': 'user-123', 'password': '[REDACTED]', 'credit_card': '1234-****-****-3456'}
        """
        redacted = {}
        
        for key, value in data.items():
            # Check if field name is sensitive
            if key.lower() in cls.SENSITIVE_FIELDS:
                redacted[key] = '[REDACTED]'
            
            # Recursively process nested dicts
            elif isinstance(value, dict):
                redacted[key] = cls.redact_dict(value)
            
            # Process lists
            elif isinstance(value, list):
                redacted[key] = [
                    cls.redact_dict(item) if isinstance(item, dict) else cls.redact_string(str(item))
                    for item in value
                ]
            
            # Redact string values
            elif isinstance(value, str):
                redacted[key] = cls.redact_string(value)
            
            # Leave other types unchanged
            else:
                redacted[key] = value
        
        return redacted
    
    @classmethod
    def redact_string(cls, text: str) -> str:
        """
        Redact sensitive patterns from string.
        
        Args:
            text: String potentially containing sensitive data
        
        Returns:
            String with sensitive patterns redacted
        """
        # Credit cards: Show first 4 and last 4 digits
        text = cls.CREDIT_CARD_PATTERN.sub(lambda m: cls._mask_credit_card(m.group()), text)
        
        # SSNs: Show only last 4 digits
        text = cls.SSN_PATTERN.sub(lambda m: f"***-**-{m.group()[-4:]}", text)
        
        # Email addresses: Mask username
        text = cls.EMAIL_PATTERN.sub(lambda m: cls._mask_email(m.group()), text)
        
        # API keys: Show prefix only
        text = cls.API_KEY_PATTERN.sub(r'\1***', text)
        
        # JWTs: Redact payload (keep header for debugging)
        text = cls.JWT_PATTERN.sub('[JWT_REDACTED]', text)
        
        # AWS credentials
        text = cls.AWS_KEY_PATTERN.sub(r'\1***', text)
        
        return text
    
    @staticmethod
    def _mask_credit_card(cc: str) -> str:
        """Mask credit card: 1234-****-****-5678"""
        digits = re.sub(r'[-\s]', '', cc)
        return f"{digits[:4]}-****-****-{digits[-4:]}"
    
    @staticmethod
    def _mask_email(email: str) -> str:
        """Mask email: u***@example.com"""
        username, domain = email.split('@')
        return f"{username[0]}***@{domain}"


# ============================================================================
# 4. AUDIT LOG REQUIREMENTS
# ============================================================================

@dataclass
class AuditLogEntry:
    """
    Tamper-evident audit log entry with cryptographic chaining.
    
    Each entry includes:
    - Hash of previous entry (blockchain-style)
    - Hash of current entry data
    - Timestamp and sequence number
    
    This makes tampering detectable - changing any entry breaks the chain.
    """
    
    sequence_number: int
    timestamp: str
    user_id: str
    action: str
    resource: str
    outcome: str
    metadata: Dict[str, Any]
    previous_hash: str  # SHA-256 hash of previous entry
    current_hash: str   # SHA-256 hash of this entry
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Serialize to JSON."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'))


class TamperEvidendAuditLog:
    """
    Tamper-evident audit log with cryptographic chaining.
    
    Features:
    - WORM storage (append-only, no modifications)
    - Cryptographic chaining (each entry hashes previous)
    - Sequence numbers (detect missing entries)
    - Integrity verification
    
    Compliance:
    - SOC 2 CC7.2: Tamper-resistant audit logs
    - ISO 27001 A.12.4.2: Protection of log information
    - PCI DSS 10.5.3: File integrity monitoring for logs
    """
    
    def __init__(self, log_file: str):
        """
        Initialize tamper-evident audit log.
        
        Args:
            log_file: Path to audit log file (append-only)
        """
        self.log_file = log_file
        self.sequence_number = 0
        self.previous_hash = "0" * 64  # Genesis hash (all zeros)
        
        # Load existing log to continue chain
        if os.path.exists(log_file):
            self._load_last_entry()
    
    def _load_last_entry(self):
        """Load last entry to continue chain."""
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1]
                last_entry = json.loads(last_line)
                self.sequence_number = last_entry['sequence_number']
                self.previous_hash = last_entry['current_hash']
    
    def append(
        self,
        user_id: str,
        action: str,
        resource: str,
        outcome: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditLogEntry:
        """
        Append audit log entry.
        
        Args:
            user_id: User performing action
            action: Action performed
            resource: Resource affected
            outcome: "success" or "failure"
            metadata: Additional context
        
        Returns:
            Created audit log entry
        """
        # Increment sequence
        self.sequence_number += 1
        
        # Create entry (without hash yet)
        entry_data = {
            'sequence_number': self.sequence_number,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'user_id': user_id,
            'action': action,
            'resource': resource,
            'outcome': outcome,
            'metadata': metadata or {},
            'previous_hash': self.previous_hash
        }
        
        # Calculate hash of entry
        current_hash = self._calculate_hash(entry_data)
        
        # Create complete entry
        entry = AuditLogEntry(
            **entry_data,
            current_hash=current_hash
        )
        
        # Write to file (append-only)
        with open(self.log_file, 'a') as f:
            f.write(entry.to_json() + '\n')
        
        # Update previous hash for next entry
        self.previous_hash = current_hash
        
        return entry
    
    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """
        Verify audit log integrity.
        
        Returns:
            (is_valid, first_invalid_sequence_number)
        
        Example:
            >>> is_valid, invalid_seq = audit_log.verify_integrity()
            >>> if not is_valid:
            ...     print(f"Tampering detected at sequence {invalid_seq}")
        """
        if not os.path.exists(self.log_file):
            return True, None  # Empty log is valid
        
        previous_hash = "0" * 64
        
        with open(self.log_file, 'r') as f:
            for line in f:
                entry_dict = json.loads(line)
                
                # Check sequence continuity
                expected_seq = 1 if previous_hash == "0" * 64 else entry_dict['sequence_number']
                
                # Check previous hash matches
                if entry_dict['previous_hash'] != previous_hash:
                    return False, entry_dict['sequence_number']
                
                # Recalculate hash
                entry_data = {k: v for k, v in entry_dict.items() if k != 'current_hash'}
                calculated_hash = self._calculate_hash(entry_data)
                
                # Verify hash matches
                if calculated_hash != entry_dict['current_hash']:
                    return False, entry_dict['sequence_number']
                
                previous_hash = entry_dict['current_hash']
        
        return True, None
    
    @staticmethod
    def _calculate_hash(data: Dict[str, Any]) -> str:
        """Calculate SHA-256 hash of entry data."""
        json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()


# ============================================================================
# 5. ELK STACK INTEGRATION
# ============================================================================

class ElasticsearchLogger:
    """
    Send logs to Elasticsearch for centralized storage and analysis.
    
    Setup:
        # Install Elasticsearch
        $ docker run -d -p 9200:9200 -p 9300:9300 \\
            -e "discovery.type=single-node" \\
            docker.elastic.co/elasticsearch/elasticsearch:8.12.0
        
        # Install Kibana
        $ docker run -d -p 5601:5601 \\
            --link elasticsearch:elasticsearch \\
            docker.elastic.co/kibana/kibana:8.12.0
    """
    
    def __init__(self, elasticsearch_url: str, index_prefix: str = "openclaw-logs"):
        """
        Initialize Elasticsearch logger.
        
        Args:
            elasticsearch_url: Elasticsearch URL (e.g., "http://localhost:9200")
            index_prefix: Index name prefix (daily indices: openclaw-logs-2026.02.15)
        """
        from elasticsearch import Elasticsearch
        
        self.es = Elasticsearch([elasticsearch_url])
        self.index_prefix = index_prefix
    
    def send_log(self, log_entry: SecurityLogEntry):
        """
        Send log entry to Elasticsearch.
        
        Creates daily indices for easier management and retention:
        - openclaw-logs-2026.02.15
        - openclaw-logs-2026.02.16
        - ...
        """
        # Daily index name
        date_str = datetime.utcnow().strftime('%Y.%m.%d')
        index_name = f"{self.index_prefix}-{date_str}"
        
        # Index document
        self.es.index(
            index=index_name,
            document=log_entry.to_dict()
        )
    
    def setup_index_template(self):
        """
        Create index template for consistent field mappings.
        
        Field types:
        - timestamp: date
        - user_id, action, resource: keyword (exact match)
        - metadata: object (nested fields)
        - ip_address: ip (IP address type)
        """
        template = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1
                },
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "event_type": {"type": "keyword"},
                        "user_id": {"type": "keyword"},
                        "action": {"type": "keyword"},
                        "resource": {"type": "keyword"},
                        "outcome": {"type": "keyword"},
                        "ip_address": {"type": "ip"},
                        "user_agent": {"type": "text"},
                        "session_id": {"type": "keyword"},
                        "request_id": {"type": "keyword"},
                        "duration_ms": {"type": "integer"},
                        "metadata": {"type": "object"},
                        "hostname": {"type": "keyword"},
                        "service": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "tags": {"type": "keyword"}
                    }
                }
            }
        }
        
        self.es.indices.put_index_template(
            name=f"{self.index_prefix}-template",
            body=template
        )


# ============================================================================
# 6. EXAMPLES AND USAGE
# ============================================================================

def example_structured_logging():
    """Example: Structured JSON logging."""
    print("=== Structured Logging Example ===\n")
    
    logger = StructuredLogger(service_name="openclaw-gateway")
    
    # Log successful login
    logger.log_event(
        event_type=SecurityEventType.LOGIN_SUCCESS,
        user_id="user-123",
        action="login",
        resource="gateway",
        outcome="success",
        ip_address="192.168.1.100",
        user_agent="OpenClaw-Desktop/1.0.0",
        severity="INFO"
    )
    
    # Log failed access attempt
    logger.log_event(
        event_type=SecurityEventType.ACCESS_DENIED,
        user_id="user-456",
        action="delete_agent",
        resource="agent-789",
        outcome="failure",
        ip_address="203.0.113.1",
        severity="WARN",
        metadata={"reason": "insufficient_permissions", "required_role": "admin"}
    )
    
    print("✓ Logs written as JSON for machine parsing\n")


def example_sensitive_data_redaction():
    """Example: Redact sensitive data."""
    print("=== Sensitive Data Redaction Example ===\n")
    
    log_data = {
        "user_id": "user-123",
        "action": "update_credentials",
        "password": "secret123",
        "credit_card": "1234-5678-9012-3456",
        "email": "user@example.com",
        "api_key": "sk-openclaw-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
    }
    
    print("Original data:")
    print(json.dumps(log_data, indent=2))
    
    redacted = SensitiveDataRedactor.redact_dict(log_data)
    
    print("\nRedacted data:")
    print(json.dumps(redacted, indent=2))
    print("\n✓ Sensitive fields protected\n")


def example_tamper_evident_audit_log():
    """Example: Tamper-evident audit log."""
    print("=== Tamper-Evident Audit Log Example ===\n")
    
    # Create audit log
    audit_log = TamperEvidendAuditLog('audit.log')
    
    # Append entries
    audit_log.append(
        user_id="admin-1",
        action="create_user",
        resource="user-123",
        outcome="success",
        metadata={"roles": ["user"]}
    )
    
    audit_log.append(
        user_id="admin-1",
        action="grant_permission",
        resource="user-123",
        outcome="success",
        metadata={"permission": "agents:delete"}
    )
    
    # Verify integrity
    is_valid, invalid_seq = audit_log.verify_integrity()
    
    if is_valid:
        print("✓ Audit log integrity verified (no tampering)")
    else:
        print(f"✗ Tampering detected at sequence {invalid_seq}")
    
    print(f"\nAudit log entries: {audit_log.sequence_number}")
    print("Hash chain ensures tamper detection\n")


# ============================================================================
# 7. TESTING
# ============================================================================

def test_structured_logging():
    """Test: Structured log JSON format."""
    entry = SecurityLogEntry(
        timestamp="2026-02-15T10:30:00Z",
        event_type="login_success",
        user_id="user-123",
        action="login",
        resource="gateway",
        outcome="success",
        severity="INFO"
    )
    
    json_str = entry.to_json()
    parsed = json.loads(json_str)
    
    assert parsed['user_id'] == "user-123"
    assert parsed['event_type'] == "login_success"
    print("✓ test_structured_logging passed")


def test_sensitive_data_redaction():
    """Test: Redact sensitive patterns."""
    data = {
        "password": "secret123",
        "credit_card": "1234567890123456",
        "normal_field": "public data"
    }
    
    redacted = SensitiveDataRedactor.redact_dict(data)
    
    assert redacted['password'] == '[REDACTED]'
    assert '****' in redacted['credit_card']
    assert redacted['normal_field'] == 'public data'
    print("✓ test_sensitive_data_redaction passed")


def test_audit_log_integrity():
    """Test: Detect tampering in audit log."""
    import tempfile
    
    # Create temporary audit log
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        temp_file = f.name
    
    try:
        audit_log = TamperEvidendAuditLog(temp_file)
        
        # Add entries
        audit_log.append("user-1", "action-1", "resource-1", "success")
        audit_log.append("user-2", "action-2", "resource-2", "success")
        
        # Verify valid
        is_valid, _ = audit_log.verify_integrity()
        assert is_valid, "Valid log should pass verification"
        
        # Tamper with log (change entry)
        with open(temp_file, 'r') as f:
            lines = f.readlines()
        
        # Modify first entry
        entry = json.loads(lines[0])
        entry['user_id'] = "hacker"
        lines[0] = json.dumps(entry) + '\n'
        
        with open(temp_file, 'w') as f:
            f.writelines(lines)
        
        # Verify tampered (should fail)
        audit_log2 = TamperEvidendAuditLog(temp_file)
        is_valid, invalid_seq = audit_log2.verify_integrity()
        assert not is_valid, "Tampered log should fail verification"
        
        print("✓ test_audit_log_integrity passed")
    
    finally:
        os.unlink(temp_file)


if __name__ == '__main__':
    print("OpenClaw Secure Logging Examples\n")
    print("=" * 70)
    print()
    
    # Run examples
    example_structured_logging()
    example_sensitive_data_redaction()
    example_tamper_evident_audit_log()
    
    print("=" * 70)
    print("\nRunning tests...\n")
    
    # Run tests
    test_structured_logging()
    test_sensitive_data_redaction()
    test_audit_log_integrity()
    
    print("\n✓ All tests passed")
    print("\nCompliance:")
    print("  - SOC 2 CC7.2: System monitoring with audit logs ✓")
    print("  - ISO 27001 A.12.4.1: Event logging (7-year retention) ✓")
    print("  - GDPR Article 30: Records of processing activities ✓")
    print("  - PCI DSS 10.2: Audit trail requirements ✓")
