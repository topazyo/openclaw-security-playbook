# Developer Integration Guide

**OpenClaw Security Framework - Developer Onboarding**

Version: 1.1  
Last Updated: 2026-02-21  
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
  python -m venv .venv
  source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
  pip install click pyyaml boto3 requests jinja2 matplotlib pandas reportlab elasticsearch
   ```

3. **Run verification script**:
   ```bash
   ./scripts/verification/verify_openclaw_security.sh
   ```

### Integrate with Your Application

**Step 1: Deploy OpenClaw Agent**

```bash
# Development environment
docker-compose -f configs/examples/docker-compose-full-stack.yml up -d

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
python tools/openclaw-cli.py config validate configs/agent-config/openclaw-agent.yml
```

---

## Security Controls Integration

### Input Validation

**Example: Configure Input Validation**

```yaml
# configs/agent-config/openclaw-agent.yml
security_controls:
  input_validation:
    enabled: true
    max_payload_size_mb: 10
    allowed_content_types:
      - application/json
      - text/plain
    sanitization_rules:
      - xss
      - sql_injection
      - path_traversal
```

```bash
python tools/openclaw-cli.py config validate configs/agent-config/openclaw-agent.yml
```

### Rate Limiting

**Example: Configure Rate Limits**

```yaml
# configs/agent-config/openclaw-agent.yml
security_controls:
  rate_limiting:
    enabled: true
    algorithm: token_bucket
    requests_per_minute: 100
    burst_size: 20
    per_user_limits:
      requests_per_minute: 50
      burst_size: 10
```

### Authentication

**Example: Configure mTLS + MFA**

```yaml
# configs/agent-config/openclaw-agent.yml
security_controls:
  authentication:
    method: mTLS
    mfa_required: true
    mtls:
      enabled: true
      client_cert_required: true
```

### Encryption

**Example: Configure Encryption Controls**

```yaml
# configs/agent-config/openclaw-agent.yml
security_controls:
  encryption:
    algorithm: AES-256-GCM
    key_rotation_days: 90
    tls_enabled: true
    tls_min_version: "1.3"
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
          ./scripts/vulnerability-scanning/os-scan.sh --image ${{ matrix.image }}
      
      - name: Run dependency scan
        run: |
          npm audit --json > npm-audit.json
          pip-audit --format json > pip-audit.json
      
      - name: Create Jira tickets
        if: failure()
        run: |
          python scripts/vulnerability-scanning/create-tickets.py --input scan-results.json --severity CRITICAL
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
        entry: python tools/openclaw-cli.py config validate configs/agent-config/openclaw-agent.yml
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
