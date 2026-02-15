# Developer Integration Guide

**OpenClaw Security Framework - Developer Onboarding**

Version: 1.0  
Last Updated: 2024-01-15  
Duration: 2 hours  
Audience: Application developers, DevOps engineers

---

## Quick Start

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/openclaw/openclaw-security-playbook.git
   cd openclaw-security-playbook
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run verification script**:
   ```bash
   ./scripts/verification/verify_openclaw_security.sh
   ```

### Integrate with Your Application

**Step 1: Deploy OpenClaw Agent**

```bash
# Development environment
docker-compose -f configs/examples/docker-compose-full-stack.yml up -d --profile dev

# Production environment (Kubernetes)
kubectl apply -f configs/examples/production-k8s.yml
```

**Step 2: Configure Agent**

Edit `configs/agent-config/openclaw-agent.yml`:

```yaml
security_controls:
  input_validation:
    max_payload_size_mb: 10
    allowed_content_types: ["application/json", "text/plain"]
    
  rate_limiting:
    requests_per_minute: 100
    burst_size: 20
    
  authentication:
    method: "mTLS"
    mfa_required: true
    
  encryption:
    algorithm: "AES-256-GCM"
    key_rotation_days: 90
```

**Step 3: Test Configuration**

```bash
openclaw-cli config validate configs/agent-config/openclaw-agent.yml
```

---

## Security Controls Integration

### Input Validation

**Example: Validate User Input**

```python
from examples.security_controls.input_validation import InputValidator

validator = InputValidator({
    "max_payload_size_mb": 10,
    "allowed_content_types": ["application/json"],
    "sanitization_rules": ["xss", "sql_injection", "path_traversal"],
})

# Sanitize user input
user_comment = request.json.get("comment")
sanitized_comment = validator.sanitize_xss(user_comment)

# Check for SQL injection
if validator.detect_sql_injection(user_comment):
    return {"error": "Malicious input detected"}, 400
```

### Rate Limiting

**Example: Apply Rate Limits**

```python
from examples.security_controls.rate_limiting import RateLimiter

limiter = RateLimiter({
    "requests_per_minute": 100,
    "burst_size": 20,
    "algorithm": "token_bucket",
    "redis_url": "redis://localhost:6379/0",
})

# Check rate limit before processing request
user_id = request.headers.get("X-User-ID")

if not limiter.check_rate_limit(user_id):
    return {"error": "Rate limit exceeded"}, 429
```

### Authentication

**Example: Verify mTLS Certificate**

```python
from examples.security_controls.authentication import AuthManager

auth_manager = AuthManager({
    "methods": ["mTLS", "OAuth2"],
    "mfa_required": True,
})

# Verify client certificate
client_cert = request.environ.get("SSL_CLIENT_CERT")

if not auth_manager.verify_mtls_cert(client_cert):
    return {"error": "Invalid certificate"}, 401

# Verify MFA
mfa_code = request.headers.get("X-MFA-Code")

if not auth_manager.verify_totp(user_id, mfa_code):
    return {"error": "MFA verification failed"}, 401
```

### Encryption

**Example: Encrypt Sensitive Data**

```python
from examples.security_controls.encryption import EncryptionManager

encryption_manager = EncryptionManager({
    "algorithm": "AES-256-GCM",
    "vault_url": "http://localhost:8200",
})

# Encrypt PII data
ssn = "123-45-6789"
ciphertext, nonce = encryption_manager.encrypt(ssn.encode())

# Decrypt when needed
decrypted = encryption_manager.decrypt(ciphertext, nonce)
```

---

## Testing

### Unit Tests

Run unit tests with pytest:

```bash
# Test input validation
pytest tests/unit/test_input_validation.py -v

# Test rate limiting
pytest tests/unit/test_rate_limiting.py -v

# Test authentication
pytest tests/unit/test_authentication.py -v

# Test encryption
pytest tests/unit/test_encryption.py -v

# Run all unit tests
pytest tests/unit/ -v
```

### Integration Tests

```bash
# Test playbook procedures
pytest tests/integration/test_playbook_procedures.py -v

# Test backup/recovery
pytest tests/integration/test_backup_recovery.py -v

# Test access reviews
pytest tests/integration/test_access_review.py -v
```

### Security Tests

```bash
# Test policy compliance
pytest tests/security/test_policy_compliance.py -v

# Test vulnerability scanning
pytest tests/security/test_vulnerability_scanning.py -v
```

---

## CI/CD Integration

### GitHub Actions

Add security scanning workflows:

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Trivy scan
        run: |
          ./scripts/discovery/os-scan.sh --image ${{ matrix.image }}
      
      - name: Run dependency scan
        run: |
          npm audit --json > npm-audit.json
          pip-audit --format json > pip-audit.json
      
      - name: Create Jira tickets
        if: failure()
        run: |
          python scripts/incident-response/create-tickets.py --severity CRITICAL
```

### Pre-commit Hooks

Install pre-commit hooks for local validation:

```bash
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: openclaw-config-validate
        name: Validate OpenClaw Config
        entry: openclaw-cli config validate
        language: system
        files: \\.yml$
```

---

## Monitoring Integration

### Prometheus Metrics

Expose metrics for monitoring:

```python
from prometheus_client import Counter, Histogram

# Request metrics
request_counter = Counter("openclaw_requests_total", "Total requests", ["method", "endpoint"])
request_duration = Histogram("openclaw_request_duration_seconds", "Request duration")

@app.route("/api/v1/resource")
@request_duration.time()
def resource():
    request_counter.labels(method="GET", endpoint="/api/v1/resource").inc()
    return {"status": "ok"}
```

### Elasticsearch Logging

Send logs to Elasticsearch:

```python
import logging
from elasticsearch import Elasticsearch

es = Elasticsearch(["http://elk.openclaw.ai:9200"])

logger = logging.getLogger("openclaw")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}'))
logger.addHandler(handler)

logger.info("Request processed", extra={
    "user_id": user_id,
    "endpoint": request.path,
    "duration_ms": duration,
})
```

---

## Troubleshooting

### Common Issues

**Issue: Rate limit exceeded during development**

Solution: Use development environment overrides:

```bash
openclaw-agent --config openclaw-agent.yml --env development
```

This sets `rate_limiting.requests_per_minute: 1000` (relaxed).

**Issue: MFA required but not configured**

Solution: Disable MFA in development:

```yaml
# environment-overrides.yml
development:
  security_controls:
    authentication:
      mfa_required: false
```

**Issue: Certificate verification fails**

Solution: Use self-signed certs in development:

```yaml
development:
  mcp_server:
    tls_config:
      verify_certs: false
```

---

## Additional Resources

- **API Documentation**: [docs/api/](../docs/api/) (if available)
- **Security Guides**: [docs/guides/](../docs/guides/)
- **Examples**: [examples/](../examples/)
- **Troubleshooting**: [docs/troubleshooting/](../docs/troubleshooting/)

---

**Questions? Contact dev-support@openclaw.ai**
