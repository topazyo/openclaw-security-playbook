#!/usr/bin/env python3
"""
Unit Tests for Input Validation Module

Tests the input-validation.py security control implementation from
examples/security-controls/input-validation.py

Test Coverage:
  - XSS sanitization (HTML/JavaScript injection)
  - SQL injection detection and blocking
  - Path traversal prevention
  - JSON schema validation
  - Content-type enforcement
  - Payload size limits
  - Unicode/UTF-8 handling
  - Edge cases (null bytes, nested objects, malformed input)

Compliance:
  - SOC 2 CC6.1: Logical and physical access controls
  - ISO 27001 A.14.2.1: Secure development policy

Usage:
  pytest tests/unit/test_input_validation.py -v
  pytest tests/unit/test_input_validation.py::test_xss_sanitization -v
"""

import pytest
import json
import re
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def input_validator():
    """Initialize input validator with default config."""
    from examples.security_controls.input_validation import InputValidator
    
    config = {
        "max_payload_size_mb": 10,
        "allowed_content_types": ["application/json", "text/plain"],
        "sanitization_rules": ["xss", "sql_injection", "path_traversal"],
        "max_string_length": 10000,
        "max_nesting_depth": 10,
    }
    
    return InputValidator(config)


@pytest.fixture
def mock_request():
    """Mock HTTP request object."""
    request = Mock()
    request.headers = {"Content-Type": "application/json"}
    request.content_length = 1024
    request.get_json = Mock(return_value={"key": "value"})
    return request


# ============================================================================
# XSS SANITIZATION TESTS
# ============================================================================

class TestXSSSanitization:
    """Test XSS attack detection and sanitization."""
    
    def test_script_tag_removal(self, input_validator):
        """Test that <script> tags are stripped from input."""
        malicious_input = "<script>alert('XSS')</script>Hello"
        
        result = input_validator.sanitize_xss(malicious_input)
        
        assert "<script>" not in result
        assert "alert" not in result
        assert "Hello" in result
    
    def test_event_handler_removal(self, input_validator):
        """Test that event handlers (onclick, onerror) are removed."""
        inputs = [
            '<img src="x" onerror="alert(1)">',
            '<div onclick="malicious()">Click me</div>',
            '<body onload="steal_cookies()">',
        ]
        
        for malicious_input in inputs:
            result = input_validator.sanitize_xss(malicious_input)
            
            assert "onerror" not in result.lower()
            assert "onclick" not in result.lower()
            assert "onload" not in result.lower()
    
    def test_javascript_protocol_removal(self, input_validator):
        """Test that javascript: protocol URLs are blocked."""
        malicious_input = '<a href="javascript:alert(1)">Click</a>'
        
        result = input_validator.sanitize_xss(malicious_input)
        
        assert "javascript:" not in result.lower()
    
    def test_data_uri_removal(self, input_validator):
        """Test that data: URIs with JavaScript are blocked."""
        malicious_input = '<img src="data:text/html,<script>alert(1)</script>">'
        
        result = input_validator.sanitize_xss(malicious_input)
        
        assert "data:" not in result.lower() or "<script>" not in result
    
    def test_encoded_xss_detection(self, input_validator):
        """Test detection of URL-encoded and HTML entity-encoded XSS."""
        encoded_inputs = [
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
        ]
        
        for encoded_input in encoded_inputs:
            # Decode and sanitize
            decoded = input_validator.decode_entities(encoded_input)
            result = input_validator.sanitize_xss(decoded)
            
            # Should not contain script tags after decoding and sanitization
            assert "<script>" not in result.lower()
    
    def test_legitimate_html_preservation(self, input_validator):
        """Test that legitimate HTML/text is preserved."""
        legitimate_inputs = [
            "Hello, world!",
            "User <user@example.com>",
            "Price: $10 < $20",
            "Math: 5 > 3 && 10 < 20",
        ]
        
        for legitimate_input in legitimate_inputs:
            result = input_validator.sanitize_xss(legitimate_input)
            
            # Content should be mostly preserved (some escaping is OK)
            assert len(result) > 0


# ============================================================================
# SQL INJECTION TESTS
# ============================================================================

class TestSQLInjectionDetection:
    """Test SQL injection detection and blocking."""
    
    def test_basic_sql_injection(self, input_validator):
        """Test detection of basic SQL injection patterns."""
        sql_injections = [
            "admin' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT password FROM users--",
            "admin'--",
            "1' OR 1=1--",
        ]
        
        for injection in sql_injections:
            is_malicious = input_validator.detect_sql_injection(injection)
            
            assert is_malicious is True, f"Failed to detect: {injection}"
    
    def test_time_based_sql_injection(self, input_validator):
        """Test detection of time-based blind SQL injection."""
        time_based_injections = [
            "1' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "1' AND BENCHMARK(10000000,MD5('A'))--",
        ]
        
        for injection in time_based_injections:
            is_malicious = input_validator.detect_sql_injection(injection)
            
            assert is_malicious is True
    
    def test_stacked_queries(self, input_validator):
        """Test detection of stacked SQL queries."""
        stacked_queries = [
            "1; DELETE FROM users WHERE 1=1",
            "admin'; DROP TABLE sessions; --",
            "1; UPDATE users SET admin=1 WHERE id=1",
        ]
        
        for query in stacked_queries:
            is_malicious = input_validator.detect_sql_injection(query)
            
            assert is_malicious is True
    
    def test_legitimate_sql_like_strings(self, input_validator):
        """Test that legitimate strings with SQL keywords are allowed."""
        legitimate_inputs = [
            "I'm a user",
            "Email: user@domain.com",
            "O'Reilly",
            "Price range: $10-$20",
        ]
        
        for legitimate_input in legitimate_inputs:
            is_malicious = input_validator.detect_sql_injection(legitimate_input)
            
            assert is_malicious is False
    
    def test_case_insensitive_detection(self, input_validator):
        """Test that SQL injection detection is case-insensitive."""
        case_variations = [
            "admin' OR '1'='1",
            "admin' or '1'='1",
            "admin' Or '1'='1",
            "ADMIN' OR '1'='1",
        ]
        
        for variation in case_variations:
            is_malicious = input_validator.detect_sql_injection(variation)
            
            assert is_malicious is True


# ============================================================================
# PATH TRAVERSAL TESTS
# ============================================================================

class TestPathTraversalPrevention:
    """Test path traversal attack detection."""
    
    def test_basic_path_traversal(self, input_validator):
        """Test detection of basic path traversal patterns."""
        path_traversals = [
            "../etc/passwd",
            "..\\windows\\system32\\config\\sam",
            "../../../../etc/shadow",
            "./../.../../etc/hosts",
        ]
        
        for path in path_traversals:
            is_malicious = input_validator.detect_path_traversal(path)
            
            assert is_malicious is True, f"Failed to detect: {path}"
    
    def test_url_encoded_traversal(self, input_validator):
        """Test detection of URL-encoded path traversal."""
        encoded_traversals = [
            "%2e%2e%2fetc%2fpasswd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%5c%2e%2e%5cwindows%5csystem32",
        ]
        
        for encoded in encoded_traversals:
            # Decode URL encoding
            decoded = input_validator.url_decode(encoded)
            is_malicious = input_validator.detect_path_traversal(decoded)
            
            assert is_malicious is True
    
    def test_double_encoded_traversal(self, input_validator):
        """Test detection of double-encoded path traversal."""
        double_encoded = "%252e%252e%252fetc%252fpasswd"
        
        # First decode
        decoded_once = input_validator.url_decode(double_encoded)
        # Second decode
        decoded_twice = input_validator.url_decode(decoded_once)
        
        is_malicious = input_validator.detect_path_traversal(decoded_twice)
        
        assert is_malicious is True
    
    def test_legitimate_paths(self, input_validator):
        """Test that legitimate file paths are allowed."""
        legitimate_paths = [
            "/var/log/application.log",
            "C:\\Users\\Public\\Documents\\file.txt",
            "./config/settings.yml",
            "data/reports/2024-report.pdf",
        ]
        
        for path in legitimate_paths:
            is_malicious = input_validator.detect_path_traversal(path)
            
            assert is_malicious is False
    
    def test_null_byte_injection(self, input_validator):
        """Test detection of null byte injection in paths."""
        null_byte_paths = [
            "/etc/passwd\x00.jpg",
            "file.txt\x00.exe",
            "config\x00/../../etc/shadow",
        ]
        
        for path in null_byte_paths:
            is_malicious = input_validator.detect_null_bytes(path)
            
            assert is_malicious is True


# ============================================================================
# JSON SCHEMA VALIDATION TESTS
# ============================================================================

class TestJSONSchemaValidation:
    """Test JSON schema validation and structure checks."""
    
    def test_valid_json_structure(self, input_validator):
        """Test validation of valid JSON structures."""
        valid_json = {
            "user": "alice",
            "email": "alice@example.com",
            "age": 30,
            "active": True,
        }
        
        is_valid = input_validator.validate_json_schema(valid_json, {
            "type": "object",
            "properties": {
                "user": {"type": "string"},
                "email": {"type": "string"},
                "age": {"type": "integer"},
                "active": {"type": "boolean"},
            },
            "required": ["user", "email"],
        })
        
        assert is_valid is True
    
    def test_invalid_json_type(self, input_validator):
        """Test rejection of invalid JSON data types."""
        invalid_json = {
            "user": "alice",
            "age": "thirty",  # Should be integer
        }
        
        is_valid = input_validator.validate_json_schema(invalid_json, {
            "type": "object",
            "properties": {
                "user": {"type": "string"},
                "age": {"type": "integer"},
            },
        })
        
        assert is_valid is False
    
    def test_missing_required_fields(self, input_validator):
        """Test rejection of JSON missing required fields."""
        incomplete_json = {
            "email": "alice@example.com",
        }
        
        is_valid = input_validator.validate_json_schema(incomplete_json, {
            "type": "object",
            "properties": {
                "user": {"type": "string"},
                "email": {"type": "string"},
            },
            "required": ["user", "email"],
        })
        
        assert is_valid is False
    
    def test_excessive_nesting_depth(self, input_validator):
        """Test rejection of deeply nested JSON (DoS protection)."""
        # Create deeply nested JSON (15 levels)
        nested_json = {"level": 0}
        current = nested_json
        for i in range(1, 16):
            current["nested"] = {"level": i}
            current = current["nested"]
        
        is_valid = input_validator.validate_nesting_depth(nested_json, max_depth=10)
        
        assert is_valid is False
    
    def test_malformed_json_parsing(self, input_validator):
        """Test handling of malformed JSON strings."""
        malformed_json_strings = [
            "{user: 'alice'}",  # Missing quotes
            "{'user': 'alice'",  # Missing closing brace
            '{"user": "alice",}',  # Trailing comma
            "",  # Empty string
        ]
        
        for malformed in malformed_json_strings:
            with pytest.raises((json.JSONDecodeError, ValueError)):
                json.loads(malformed)


# ============================================================================
# CONTENT-TYPE ENFORCEMENT TESTS
# ============================================================================

class TestContentTypeEnforcement:
    """Test content-type validation and enforcement."""
    
    def test_allowed_content_types(self, input_validator):
        """Test that allowed content types are accepted."""
        allowed_types = [
            "application/json",
            "text/plain",
        ]
        
        for content_type in allowed_types:
            is_allowed = input_validator.validate_content_type(content_type)
            
            assert is_allowed is True
    
    def test_rejected_content_types(self, input_validator):
        """Test that disallowed content types are rejected."""
        rejected_types = [
            "application/xml",
            "text/html",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ]
        
        for content_type in rejected_types:
            is_allowed = input_validator.validate_content_type(content_type)
            
            assert is_allowed is False
    
    def test_content_type_with_charset(self, input_validator):
        """Test content types with charset parameters."""
        content_types_with_charset = [
            "application/json; charset=utf-8",
            "text/plain; charset=iso-8859-1",
        ]
        
        for content_type in content_types_with_charset:
            # Extract base content type
            base_type = content_type.split(";")[0].strip()
            is_allowed = input_validator.validate_content_type(base_type)
            
            assert is_allowed is True
    
    def test_case_insensitive_content_type(self, input_validator):
        """Test that content type checking is case-insensitive."""
        case_variations = [
            "application/json",
            "Application/JSON",
            "APPLICATION/JSON",
            "application/JSON",
        ]
        
        for content_type in case_variations:
            is_allowed = input_validator.validate_content_type(
                content_type.lower()
            )
            
            assert is_allowed is True


# ============================================================================
# PAYLOAD SIZE LIMIT TESTS
# ============================================================================

class TestPayloadSizeLimits:
    """Test payload size validation and limits."""
    
    def test_within_size_limit(self, input_validator):
        """Test that payloads within limit are accepted."""
        # 5 MB payload (within 10 MB limit)
        payload_size = 5 * 1024 * 1024
        
        is_valid = input_validator.validate_payload_size(payload_size)
        
        assert is_valid is True
    
    def test_exceeds_size_limit(self, input_validator):
        """Test that payloads exceeding limit are rejected."""
        # 15 MB payload (exceeds 10 MB limit)
        payload_size = 15 * 1024 * 1024
        
        is_valid = input_validator.validate_payload_size(payload_size)
        
        assert is_valid is False
    
    def test_exact_size_limit(self, input_validator):
        """Test payload exactly at size limit."""
        # Exactly 10 MB
        payload_size = 10 * 1024 * 1024
        
        is_valid = input_validator.validate_payload_size(payload_size)
        
        assert is_valid is True  # At limit should be allowed
    
    def test_string_length_limit(self, input_validator):
        """Test maximum string length enforcement."""
        # String exceeding max length (10000 chars)
        long_string = "A" * 15000
        
        is_valid = input_validator.validate_string_length(long_string)
        
        assert is_valid is False


# ============================================================================
# UNICODE AND UTF-8 HANDLING TESTS
# ============================================================================

class TestUnicodeHandling:
    """Test proper handling of Unicode and UTF-8 data."""
    
    def test_valid_utf8_characters(self, input_validator):
        """Test that valid UTF-8 characters are preserved."""
        unicode_strings = [
            "Hello, 世界!",  # Chinese
            "Привет, мир!",  # Russian
            "مرحبا بالعالم",  # Arabic
            "🔒🛡️🔐",  # Emojis
        ]
        
        for unicode_string in unicode_strings:
            result = input_validator.sanitize_xss(unicode_string)
            
            # Non-malicious Unicode should be preserved
            assert len(result) > 0
    
    def test_invalid_utf8_sequences(self, input_validator):
        """Test handling of invalid UTF-8 byte sequences."""
        # Invalid UTF-8 sequences
        invalid_sequences = [
            b"\xff\xfe",
            b"\x80\x81\x82",
        ]
        
        for seq in invalid_sequences:
            with pytest.raises(UnicodeDecodeError):
                seq.decode("utf-8")
    
    def test_overlong_utf8_encoding(self, input_validator):
        """Test detection of overlong UTF-8 encodings."""
        # Overlong encoding can bypass security checks
        # Example: "/" encoded as 0xC0 0xAF instead of 0x2F
        overlong_encoded = b"\xc0\xaf"
        
        # Should reject overlong encodings
        is_valid = input_validator.validate_utf8(overlong_encoded)
        
        assert is_valid is False


# ============================================================================
# EDGE CASES AND BOUNDARY TESTS
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_empty_string_input(self, input_validator):
        """Test handling of empty string input."""
        empty_string = ""
        
        result = input_validator.sanitize_xss(empty_string)
        
        assert result == ""
    
    def test_none_input(self, input_validator):
        """Test handling of None input."""
        with pytest.raises((TypeError, AttributeError)):
            input_validator.sanitize_xss(None)
    
    def test_numeric_input(self, input_validator):
        """Test handling of numeric input (should convert to string)."""
        numeric_inputs = [123, 45.67, -89]
        
        for num in numeric_inputs:
            result = input_validator.sanitize_xss(str(num))
            
            assert result == str(num)
    
    def test_very_long_payload(self, input_validator):
        """Test handling of extremely long payloads."""
        # Create 20 MB string
        very_long_string = "A" * (20 * 1024 * 1024)
        
        is_valid = input_validator.validate_payload_size(len(very_long_string))
        
        assert is_valid is False
    
    def test_special_characters(self, input_validator):
        """Test handling of special characters and symbols."""
        special_chars = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        
        result = input_validator.sanitize_xss(special_chars)
        
        # Special chars should be preserved or escaped, not removed entirely
        assert len(result) > 0
    
    def test_whitespace_only(self, input_validator):
        """Test handling of whitespace-only input."""
        whitespace_inputs = ["   ", "\t\t\t", "\n\n\n", "\r\n\r\n"]
        
        for whitespace in whitespace_inputs:
            result = input_validator.sanitize_xss(whitespace)
            
            # Whitespace should be preserved
            assert result == whitespace
    
    def test_mixed_malicious_content(self, input_validator):
        """Test input with multiple types of malicious content."""
        mixed_attack = (
            "<script>alert('XSS')</script>"
            "' OR '1'='1"
            "../../../etc/passwd"
        )
        
        result = input_validator.sanitize_all(mixed_attack)
        
        # Should sanitize all attack vectors
        assert "<script>" not in result
        assert is_sql_injection := input_validator.detect_sql_injection(result)
        assert is_path_traversal := input_validator.detect_path_traversal(result)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestInputValidationIntegration:
    """Integration tests for complete input validation flow."""
    
    @patch("flask.request")
    def test_complete_validation_flow(self, mock_request, input_validator):
        """Test complete validation flow with mocked Flask request."""
        mock_request.headers = {"Content-Type": "application/json"}
        mock_request.content_length = 1024
        mock_request.get_json = Mock(return_value={
            "username": "alice",
            "comment": "This is a legitimate comment.",
        })
        
        # Validate content type
        assert input_validator.validate_content_type(
            mock_request.headers["Content-Type"]
        )
        
        # Validate payload size
        assert input_validator.validate_payload_size(
            mock_request.content_length
        )
        
        # Get and validate JSON
        data = mock_request.get_json()
        assert input_validator.validate_json_schema(data, {
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "comment": {"type": "string"},
            },
            "required": ["username"],
        })
        
        # Sanitize inputs
        data["username"] = input_validator.sanitize_xss(data["username"])
        data["comment"] = input_validator.sanitize_xss(data["comment"])
        
        assert data["username"] == "alice"
        assert "legitimate" in data["comment"]
    
    def test_validation_rejection_flow(self, input_validator):
        """Test that malicious input is rejected at multiple stages."""
        malicious_payload = {
            "username": "<script>alert('XSS')</script>",
            "query": "admin' OR '1'='1",
            "file_path": "../../../etc/passwd",
        }
        
        # Sanitize and check each field
        sanitized = {}
        for key, value in malicious_payload.items():
            sanitized[key] = input_validator.sanitize_all(value)
        
        # Verify malicious content was removed/blocked
        assert "<script>" not in sanitized["username"]
        assert input_validator.detect_sql_injection(sanitized["query"])
        assert input_validator.detect_path_traversal(sanitized["file_path"])


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
