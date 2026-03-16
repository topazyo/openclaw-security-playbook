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

2. **Install the package and dependencies**:
   ```bash
  python -m venv .venv
  source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
  pip install -e .
   ```

3. **Run verification script**:
   ```bash
   ./scripts/verification/verify_openclaw_security.sh
   ```

### Integrate with Your Application

**Prerequisites — required before any `docker compose` or `kubectl` command:**

| Variable | Purpose |
|---|---|
| `CLAWDBOT_IMAGE` | Your registry and image tag (e.g. `yourregistry/clawdbot:2.0.0`). No official published image exists for this playbook. |
| `GATEWAY_TOKEN` | Gateway authentication secret (generate with `openssl rand -base64 32`). |
| `ANTHROPIC_API_KEY` | Anthropic API key for the downstream runtime. |
| `GRAFANA_PASSWORD` | Grafana admin password. |

Set these in your shell or in a local `.env` file before proceeding:

```bash
export CLAWDBOT_IMAGE="yourregistry/clawdbot:2.0.0"
export GATEWAY_TOKEN="$(openssl rand -base64 32)"
export ANTHROPIC_API_KEY="sk-ant-..."
export GRAFANA_PASSWORD="$(openssl rand -base64 16)"
```

**Step 1: Deploy OpenClaw Agent**

```bash
# Development environment (syntax-check first, then bring up)
docker compose -f configs/examples/docker-compose-full-stack.yml config   # validate
docker compose -f configs/examples/docker-compose-full-stack.yml up -d

# Production environment (Kubernetes)
# IMPORTANT: configs/examples/production-k8s.yml is a reference template.
# You must substitute the CLAWDBOT_IMAGE, GATEWAY_TOKEN, and ANTHROPIC_API_KEY
# placeholders before applying. The file uses shell-style placeholder syntax;
# review it carefully and supply your organisation's image and secret management
# path before running kubectl apply.
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
openclaw-cli config validate configs/agent-config/openclaw-agent.yml
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

The repo ships a maintained security-scan workflow. Reference it directly rather than copying stale snippets:

```
.github/workflows/security-scan.yml
```

Key characteristics of the maintained workflow (as of this writing):

- Uses `actions/checkout@v4`
- Builds repo-native images (`openclaw-playbook:latest`, `clawdbot-gateway:ci`, `clawdbot-agent:ci`) via `scripts/hardening/docker/Dockerfile.hardened`
- Scans filesystem and images with `aquasecurity/trivy-action@0.24.0` (pinned, not `@master`)
- Uploads SARIF results to the GitHub Security tab

To add scanning to a downstream repo, reference the workflow structure from `.github/workflows/security-scan.yml` and adapt image names and build targets to your context. Never copy the snippet below from older training docs — use the live workflow file as the single source of truth.

```yaml
# Minimal example — adapt from .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]
jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Trivy filesystem scan
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'CRITICAL,HIGH'
          format: 'sarif'
          output: 'trivy-results.sarif'
      - name: Upload results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'
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
        entry: openclaw-cli config validate configs/agent-config/openclaw-agent.yml
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
