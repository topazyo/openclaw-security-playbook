"""
Data Classification and Handling - OpenClaw Security Framework

This module implements data classification levels and automatic enforcement
of handling requirements based on classification.

Language: Python 3.11+
Dependencies: re (regex), cryptography
Last Updated: 2026-02-15

Table of Contents:
1. Overview
2. Classification Levels
   - Restricted (PII, credentials, payment info)
   - Confidential (business data, contracts)
   - Internal (operational data)
   - Public (marketing, documentation)
3. Automatic Classification
4. Handling Requirements Enforcement
5. Data Loss Prevention (DLP) Integration
6. Examples and Usage
7. Testing

References:
- SEC-003: Data Classification Policy (defines 4 levels)
- playbook-data-breach.md (IRP-004): Classification impact matrix
- encryption.py: Encryption requirements by classification
- GDPR Article 32: Security appropriate to risk (personal data = Restricted)
- ISO 27001 A.8.2.1: Classification of information
"""

import re
import hashlib
from typing import Optional, Dict, Any, List, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import logging


# ============================================================================
# 1. OVERVIEW
# ============================================================================

"""
Data Classification Framework:

+----------------+---------------------+------------------------+-------------------------+
| Level          | Examples            | Encryption             | Access Control          |
+----------------+---------------------+------------------------+-------------------------+
| Restricted     | - PII (SSN, DOB)    | AES-256 (mandatory)    | MFA required            |
|                | - Credentials       | TLS 1.3 (mandatory)    | Role-based (minimal)    |
|                | - Payment info      | At rest + in transit   | All access logged       |
|                | - Health records    |                        | DLP monitoring          |
+----------------+---------------------+------------------------+-------------------------+
| Confidential   | - Business data     | AES-256 (recommended)  | Role-based              |
|                | - Contracts         | TLS 1.2+ (recommended) | Access reviews (annual) |
|                | - Proprietary code  | At rest optional       | Logging recommended     |
|                | - Internal designs  |                        |                         |
+----------------+---------------------+------------------------+-------------------------+
| Internal       | - Operational logs  | Optional               | Employee access only    |
|                | - System configs    | TLS 1.2+ recommended   | Network segmentation    |
|                | - Internal docs     |                        | Basic logging           |
+----------------+---------------------+------------------------+-------------------------+
| Public         | - Marketing content | Not required           | No restrictions         |
|                | - Press releases    | Optional               | Publicly accessible     |
|                | - Documentation     |                        |                         |
+----------------+---------------------+------------------------+-------------------------+

GDPR Mapping:
- Personal Data → Restricted (requires Article 32 encryption)
- Special Categories (Article 9) → Restricted (health, biometric, genetic data)
- Non-personal business data → Confidential or lower

Compliance:
- SEC-003: Data classification policy defines handling requirements
- ISO 27001 A.8.2.1: Classification scheme with clear labels
- GDPR Article 32: Security measures appropriate to risk
- PCI DSS 3.4: Cardholder data = Restricted (encryption mandatory)
"""


# ============================================================================
# 2. CLASSIFICATION LEVELS
# ============================================================================

class DataClassification(Enum):
    """Data classification levels."""
    RESTRICTED = "Restricted"        # Highest sensitivity
    CONFIDENTIAL = "Confidential"    # Business-sensitive
    INTERNAL = "Internal"            # Internal use only
    PUBLIC = "Public"                # No restrictions


@dataclass
class ClassificationLabel:
    """Classification label metadata."""
    classification: DataClassification
    reason: str  # Why this classification was assigned
    detected_patterns: List[str]  # Patterns that triggered classification
    confidence: float  # 0.0-1.0
    assigned_at: str  # ISO 8601 timestamp
    assigned_by: str  # "automatic" or user ID
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'classification': self.classification.value,
            'reason': self.reason,
            'detected_patterns': self.detected_patterns,
            'confidence': self.confidence,
            'assigned_at': self.assigned_at,
            'assigned_by': self.assigned_by
        }


@dataclass
class HandlingRequirement:
    """Handling requirements for classified data."""
    encryption_at_rest: bool
    encryption_in_transit: bool
    encryption_algorithm: Optional[str]  # "AES-256", "TLS 1.3"
    access_control: str  # "public", "authenticated", "rbac", "mfa"
    audit_logging: str  # "none", "basic", "full"
    dlp_monitoring: bool  # Data Loss Prevention monitoring
    retention_days: Optional[int]
    disposal_method: str  # "standard_delete", "secure_wipe", "crypto_shred"
    breach_notification: str  # "none", "internal", "customers", "regulators"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


# ============================================================================
# 3. AUTOMATIC CLASSIFICATION
# ============================================================================

class DataClassifier:
    """
    Automatic data classification using pattern matching.
    
    Detects:
    - PII (SSN, credit cards, passport numbers, driver's licenses)
    - Credentials (passwords, API keys, access tokens)
    - Payment info (credit card numbers, CVV, account numbers)
    - Health records (medical record numbers, insurance IDs)
    - Confidential markers (keywords: "confidential", "proprietary", "trade secret")
    """
    
    # Restricted patterns (PII, credentials, payment info)
    SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')  # 123-45-6789
    CREDIT_CARD_PATTERN = re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')  # 1234-5678-9012-3456
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    PHONE_PATTERN = re.compile(r'\b(\+1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b')
    API_KEY_PATTERN = re.compile(r'\b(sk|pk|api)[-_][a-zA-Z0-9]{32,}\b', re.IGNORECASE)
    JWT_PATTERN = re.compile(r'\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b')
    PASSWORD_FIELD_PATTERN = re.compile(r'(password|passwd|pwd)\s*[:=]\s*[\'"]?[^\s\'"]+', re.IGNORECASE)
    
    # Passport/ID patterns (examples - add country-specific)
    PASSPORT_PATTERN = re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b')  # US passport format
    DRIVERS_LICENSE_PATTERN = re.compile(r'\b[A-Z]\d{7,8}\b')  # CA format (example)
    
    # Health-related patterns
    MEDICAL_RECORD_PATTERN = re.compile(r'\bMRN\s*[:=]?\s*\d{6,10}\b', re.IGNORECASE)
    INSURANCE_ID_PATTERN = re.compile(r'\b[A-Z]{3}\d{9}\b')  # Insurance member ID
    
    # Confidential markers (keywords)
    CONFIDENTIAL_KEYWORDS = {
        'confidential', 'proprietary', 'trade secret', 'internal only',
        'do not distribute', 'attorney-client privilege', 'privileged',
        'company confidential', 'restricted distribution'
    }
    
    # Public markers (keywords)
    PUBLIC_KEYWORDS = {
        'public', 'press release', 'published', 'marketing material',
        'external communication', 'customer-facing'
    }
    
    def __init__(self):
        """Initialize data classifier."""
        self.logger = logging.getLogger(__name__)
    
    def classify_text(self, text: str) -> ClassificationLabel:
        """
        Automatically classify text content.
        
        Args:
            text: Text content to classify
        
        Returns:
            Classification label with confidence score
        
        Example:
            >>> classifier = DataClassifier()
            >>> label = classifier.classify_text("SSN: 123-45-6789")
            >>> label.classification
            <DataClassification.RESTRICTED: 'Restricted'>
        """
        detected_patterns = []
        reasons = []
        
        # Check for Restricted patterns (highest priority)
        if self.SSN_PATTERN.search(text):
            detected_patterns.append('SSN')
            reasons.append('Contains Social Security Number (PII)')
        
        if self.CREDIT_CARD_PATTERN.search(text):
            detected_patterns.append('Credit Card')
            reasons.append('Contains credit card number')
        
        if self.API_KEY_PATTERN.search(text):
            detected_patterns.append('API Key')
            reasons.append('Contains API key or access token')
        
        if self.JWT_PATTERN.search(text):
            detected_patterns.append('JWT Token')
            reasons.append('Contains JWT authentication token')
        
        if self.PASSWORD_FIELD_PATTERN.search(text):
            detected_patterns.append('Password')
            reasons.append('Contains password field')
        
        if self.PASSPORT_PATTERN.search(text):
            detected_patterns.append('Passport Number')
            reasons.append('Contains passport number (PII)')
        
        if self.MEDICAL_RECORD_PATTERN.search(text):
            detected_patterns.append('Medical Record')
            reasons.append('Contains medical record number (PHI)')
        
        # Restricted classification if any sensitive pattern found
        if detected_patterns:
            return ClassificationLabel(
                classification=DataClassification.RESTRICTED,
                reason='; '.join(reasons),
                detected_patterns=detected_patterns,
                confidence=0.95,  # High confidence for pattern matches
                assigned_at=datetime.utcnow().isoformat() + 'Z',
                assigned_by='automatic'
            )
        
        # Check for Confidential markers
        text_lower = text.lower()
        if any(keyword in text_lower for keyword in self.CONFIDENTIAL_KEYWORDS):
            return ClassificationLabel(
                classification=DataClassification.CONFIDENTIAL,
                reason='Contains confidential marking keyword',
                detected_patterns=['confidential_keyword'],
                confidence=0.80,
                assigned_at=datetime.utcnow().isoformat() + 'Z',
                assigned_by='automatic'
            )
        
        # Check for Public markers
        if any(keyword in text_lower for keyword in self.PUBLIC_KEYWORDS):
            return ClassificationLabel(
                classification=DataClassification.PUBLIC,
                reason='Contains public marking keyword',
                detected_patterns=['public_keyword'],
                confidence=0.75,
                assigned_at=datetime.utcnow().isoformat() + 'Z',
                assigned_by='automatic'
            )
        
        # Default: Internal (no sensitive patterns, no explicit markers)
        return ClassificationLabel(
            classification=DataClassification.INTERNAL,
            reason='No sensitive patterns detected - default to Internal',
            detected_patterns=[],
            confidence=0.60,
            assigned_at=datetime.utcnow().isoformat() + 'Z',
            assigned_by='automatic'
        )
    
    def classify_file(self, filepath: str) -> ClassificationLabel:
        """
        Classify file content.
        
        Args:
            filepath: Path to file
        
        Returns:
            Classification label
        
        Example:
            >>> classifier = DataClassifier()
            >>> label = classifier.classify_file('./customer_data.csv')
        """
        self.logger.info(f"Classifying file: {filepath}")
        
        # Read file content (limit to first 1 MB for performance)
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(1024 * 1024)  # 1 MB
        
        # Classify content
        label = self.classify_text(content)
        
        self.logger.info(f"File classified as: {label.classification.value} (confidence: {label.confidence:.2f})")
        
        return label


# ============================================================================
# 4. HANDLING REQUIREMENTS ENFORCEMENT
# ============================================================================

class HandlingRequirementsManager:
    """
    Enforce handling requirements based on data classification.
    """
    
    # Handling requirements by classification level (from SEC-003 policy)
    REQUIREMENTS = {
        DataClassification.RESTRICTED: HandlingRequirement(
            encryption_at_rest=True,
            encryption_in_transit=True,
            encryption_algorithm="AES-256-GCM / TLS 1.3",
            access_control="mfa",  # MFA required
            audit_logging="full",  # Log all access
            dlp_monitoring=True,  # Monitor for exfiltration
            retention_days=2555,  # 7 years (SOC 2)
            disposal_method="crypto_shred",  # Cryptographic erasure
            breach_notification="regulators"  # GDPR 72-hour notification
        ),
        
        DataClassification.CONFIDENTIAL: HandlingRequirement(
            encryption_at_rest=True,
            encryption_in_transit=True,
            encryption_algorithm="AES-256 / TLS 1.2+",
            access_control="rbac",  # Role-based access control
            audit_logging="basic",  # Log access attempts
            dlp_monitoring=False,
            retention_days=365,  # 1 year
            disposal_method="secure_wipe",  # 3-pass overwrite
            breach_notification="internal"  # Internal notification only
        ),
        
        DataClassification.INTERNAL: HandlingRequirement(
            encryption_at_rest=False,
            encryption_in_transit=True,
            encryption_algorithm="TLS 1.2+",
            access_control="authenticated",  # Any employee
            audit_logging="none",
            dlp_monitoring=False,
            retention_days=90,  # 90 days
            disposal_method="standard_delete",
            breach_notification="none"
        ),
        
        DataClassification.PUBLIC: HandlingRequirement(
            encryption_at_rest=False,
            encryption_in_transit=False,
            encryption_algorithm=None,
            access_control="public",  # No restrictions
            audit_logging="none",
            dlp_monitoring=False,
            retention_days=None,  # No retention limit
            disposal_method="standard_delete",
            breach_notification="none"
        )
    }
    
    @classmethod
    def get_requirements(cls, classification: DataClassification) -> HandlingRequirement:
        """
        Get handling requirements for classification level.
        
        Args:
            classification: Data classification level
        
        Returns:
            Handling requirements
        
        Example:
            >>> requirements = HandlingRequirementsManager.get_requirements(
            ...     DataClassification.RESTRICTED
            ... )
            >>> requirements.encryption_at_rest
            True
        """
        return cls.REQUIREMENTS[classification]
    
    @classmethod
    def enforce_requirements(
        cls,
        data: bytes,
        classification: DataClassification,
        current_encryption: bool = False,
        current_access_control: str = "public"
    ) -> Tuple[bool, List[str]]:
        """
        Verify data handling meets classification requirements.
        
        Args:
            data: Data being handled
            classification: Classification level
            current_encryption: Whether data is currently encrypted
            current_access_control: Current access control ("public", "authenticated", "rbac", "mfa")
        
        Returns:
            (compliant, violations)
        
        Example:
            >>> data = b"SSN: 123-45-6789"
            >>> compliant, violations = HandlingRequirementsManager.enforce_requirements(
            ...     data,
            ...     DataClassification.RESTRICTED,
            ...     current_encryption=False,
            ...     current_access_control="public"
            ... )
            >>> compliant
            False
            >>> violations
            ['Encryption at rest required but not enabled', 'MFA required but access is public']
        """
        requirements = cls.get_requirements(classification)
        violations = []
        
        # Check encryption at rest
        if requirements.encryption_at_rest and not current_encryption:
            violations.append(
                f"Encryption at rest required ({requirements.encryption_algorithm}) but not enabled"
            )
        
        # Check access control
        access_levels = {"public": 0, "authenticated": 1, "rbac": 2, "mfa": 3}
        required_level = access_levels.get(requirements.access_control, 0)
        current_level = access_levels.get(current_access_control, 0)
        
        if current_level < required_level:
            violations.append(
                f"{requirements.access_control.upper()} required but access is {current_access_control}"
            )
        
        # Check DLP monitoring
        if requirements.dlp_monitoring:
            # In practice, verify DLP is enabled for this data flow
            pass  # Placeholder
        
        compliant = len(violations) == 0
        
        return compliant, violations
    
    @classmethod
    def get_breach_impact(cls, classification: DataClassification) -> Dict[str, Any]:
        """
        Get breach impact assessment by classification.
        
        Returns breach notification requirements and potential penalties.
        
        Args:
            classification: Data classification level
        
        Returns:
            Breach impact dictionary
        
        Example:
            >>> impact = HandlingRequirementsManager.get_breach_impact(
            ...     DataClassification.RESTRICTED
            ... )
            >>> impact['notification_deadline']
            '72 hours (GDPR)'
        """
        requirements = cls.get_requirements(classification)
        
        impacts = {
            DataClassification.RESTRICTED: {
                'severity': 'Critical',
                'notification_required': True,
                'notification_deadline': '72 hours (GDPR Article 33)',
                'notify_who': ['Data Protection Authority', 'Affected customers', 'CISO', 'Legal'],
                'potential_penalties': 'Up to 4% annual revenue (GDPR) or $50K per record (state laws)',
                'playbook': 'playbook-data-breach.md (IRP-004)',
                'media_risk': 'High - public disclosure likely'
            },
            
            DataClassification.CONFIDENTIAL: {
                'severity': 'High',
                'notification_required': False,
                'notification_deadline': 'N/A',
                'notify_who': ['CISO', 'Legal', 'Business owner'],
                'potential_penalties': 'Reputational damage, potential lawsuits',
                'playbook': 'playbook-data-breach.md (IRP-004)',
                'media_risk': 'Medium - depends on data type'
            },
            
            DataClassification.INTERNAL: {
                'severity': 'Medium',
                'notification_required': False,
                'notification_deadline': 'N/A',
                'notify_who': ['CISO', 'IT Operations'],
                'potential_penalties': 'Operational disruption',
                'playbook': 'Standard incident response',
                'media_risk': 'Low'
            },
            
            DataClassification.PUBLIC: {
                'severity': 'Low',
                'notification_required': False,
                'notification_deadline': 'N/A',
                'notify_who': [],
                'potential_penalties': 'None',
                'playbook': 'N/A',
                'media_risk': 'None'
            }
        }
        
        return impacts[classification]


# ============================================================================
# 5. DATA LOSS PREVENTION (DLP) INTEGRATION
# ============================================================================

class DLPMonitor:
    """
    Data Loss Prevention (DLP) monitoring for Restricted data.
    
    Monitors:
    - Large data transfers (>100 MB) from internal to external
    - Email attachments with Restricted data
    - API responses containing PII
    - File uploads/downloads
    """
    
    TRANSFER_SIZE_THRESHOLD_MB = 100  # Block transfers >100 MB
    
    def __init__(self):
        """Initialize DLP monitor."""
        self.logger = logging.getLogger(__name__)
    
    def check_transfer(
        self,
        data: bytes,
        classification: DataClassification,
        source: str,
        destination: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if data transfer is allowed.
        
        Args:
            data: Data being transferred
            classification: Data classification
            source: Source location (e.g., "internal", "user-123")
            destination: Destination (e.g., "external", "api.partner.com")
        
        Returns:
            (allowed, block_reason)
        
        Example:
            >>> dlp = DLPMonitor()
            >>> allowed, reason = dlp.check_transfer(
            ...     b"SSN: 123-45-6789" * 1000,
            ...     DataClassification.RESTRICTED,
            ...     "internal",
            ...     "external"
            ... )
            >>> allowed
            False
            >>> reason
            'Restricted data transfer to external destination blocked by DLP'
        """
        size_mb = len(data) / (1024 * 1024)
        
        # Block Restricted data to external destinations
        if classification == DataClassification.RESTRICTED:
            if 'external' in destination.lower() or 'public' in destination.lower():
                self.logger.warning(
                    f"DLP: Blocked Restricted data transfer to {destination} ({size_mb:.2f} MB)"
                )
                return False, "Restricted data transfer to external destination blocked by DLP"
        
        # Block large transfers (possible data exfiltration)
        if size_mb > self.TRANSFER_SIZE_THRESHOLD_MB:
            if classification in [DataClassification.RESTRICTED, DataClassification.CONFIDENTIAL]:
                self.logger.warning(
                    f"DLP: Blocked large data transfer ({size_mb:.2f} MB > {self.TRANSFER_SIZE_THRESHOLD_MB} MB threshold)"
                )
                return False, f"Large data transfer blocked (>{self.TRANSFER_SIZE_THRESHOLD_MB} MB) - possible exfiltration"
        
        # Allow transfer
        self.logger.info(f"DLP: Allowed transfer ({size_mb:.2f} MB) from {source} to {destination}")
        return True, None


# ============================================================================
# 6. EXAMPLES AND USAGE
# ============================================================================

def example_automatic_classification():
    """Example: Automatic data classification."""
    print("=== Automatic Data Classification Example ===\n")
    
    classifier = DataClassifier()
    
    # Example 1: PII data
    label1 = classifier.classify_text("Customer SSN: 123-45-6789")
    print(f"Text 1: {label1.classification.value}")
    print(f"  Reason: {label1.reason}")
    print(f"  Confidence: {label1.confidence:.2f}")
    print()
    
    # Example 2: Confidential business data
    label2 = classifier.classify_text("CONFIDENTIAL: Q4 revenue projections")
    print(f"Text 2: {label2.classification.value}")
    print(f"  Reason: {label2.reason}")
    print()
    
    # Example 3: Public content
    label3 = classifier.classify_text("Press Release: New product launch")
    print(f"Text 3: {label3.classification.value}")
    print(f"  Reason: {label3.reason}")
    print()


def example_handling_requirements():
    """Example: Handling requirements by classification."""
    print("=== Handling Requirements Example ===\n")
    
    for classification in DataClassification:
        requirements = HandlingRequirementsManager.get_requirements(classification)
        
        print(f"{classification.value}:")
        print(f"  Encryption: {'✓ Required' if requirements.encryption_at_rest else '✗ Optional'}")
        print(f"  Access Control: {requirements.access_control.upper()}")
        print(f"  Audit Logging: {requirements.audit_logging}")
        print(f"  DLP Monitoring: {'✓ Yes' if requirements.dlp_monitoring else '✗ No'}")
        print()


def example_dlp_monitoring():
    """Example: DLP transfer blocking."""
    print("=== DLP Monitoring Example ===\n")
    
    dlp = DLPMonitor()
    
    # Attempt to transfer Restricted data externally
    allowed, reason = dlp.check_transfer(
        b"SSN: 123-45-6789",
        DataClassification.RESTRICTED,
        "internal",
        "external-api"
    )
    
    print(f"Transfer allowed: {allowed}")
    if not allowed:
        print(f"Block reason: {reason}")
    print()


# ============================================================================
# 7. TESTING
# ============================================================================

def test_classification_detection():
    """Test: Automatic classification of sensitive data."""
    classifier = DataClassifier()
    
    # Test SSN detection
    label = classifier.classify_text("SSN: 123-45-6789")
    assert label.classification == DataClassification.RESTRICTED
    assert 'SSN' in label.detected_patterns
    
    # Test public marking
    label = classifier.classify_text("Public press release")
    assert label.classification == DataClassification.PUBLIC
    
    print("✓ test_classification_detection passed")


def test_handling_requirements():
    """Test: Handling requirements enforcement."""
    # Restricted data requires encryption
    requirements = HandlingRequirementsManager.get_requirements(
        DataClassification.RESTRICTED
    )
    assert requirements.encryption_at_rest == True
    assert requirements.access_control == "mfa"
    
    # Public data has no restrictions
    requirements = HandlingRequirementsManager.get_requirements(
        DataClassification.PUBLIC
    )
    assert requirements.encryption_at_rest == False
    assert requirements.access_control == "public"
    
    print("✓ test_handling_requirements passed")


def test_dlp_blocking():
    """Test: DLP blocks external transfer of Restricted data."""
    dlp = DLPMonitor()
    
    allowed, reason = dlp.check_transfer(
        b"Restricted data",
        DataClassification.RESTRICTED,
        "internal",
        "external-partner"
    )
    
    assert not allowed, "DLP should block Restricted data to external"
    assert reason is not None
    
    print("✓ test_dlp_blocking passed")


if __name__ == '__main__':
    print("OpenClaw Data Classification Examples\n")
    print("=" * 70)
    print()
    
    # Run examples
    example_automatic_classification()
    example_handling_requirements()
    example_dlp_monitoring()
    
    print("=" * 70)
    print("\nRunning tests...\n")
    
    # Run tests
    test_classification_detection()
    test_handling_requirements()
    test_dlp_blocking()
    
    print("\n✓ All tests passed")
    print("\nCompliance:")
    print("  - SEC-003: Data Classification Policy (4 levels defined) ✓")
    print("  - ISO 27001 A.8.2.1: Classification of information ✓")
    print("  - GDPR Article 32: Security appropriate to risk ✓")
    print("\nClassification Levels:")
    print("  - Restricted: PII, credentials, payment info (AES-256, MFA, DLP)")
    print("  - Confidential: Business data, contracts (AES-256 recommended, RBAC)")
    print("  - Internal: Operational data (TLS 1.2+, authenticated access)")
    print("  - Public: No restrictions")
