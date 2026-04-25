# TOTP Enrollment Guide

Benign fixture: TOTP enrollment instructions that mention "system prompt" in a
legitimate UX-description context. Contains no dangerous skill patterns.
Used by: tests/security/test_evasion_hardening.py (Finding #10 — C5)

## Steps

1. Open your authenticator application.
2. When the system prompt appears on your device, tap **Allow**.
3. Scan the QR code displayed on the enrollment screen.
4. Enter the 6-digit verification code.

The system prompt will guide you through each step of the enrollment process.
Contact support if the system prompt does not appear within 30 seconds.
