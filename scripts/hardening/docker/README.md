# Docker Hardening Configuration for ClawdBot

> **Production-ready Docker setup with security hardening, orchestration, and monitoring**

This directory contains hardened Docker configurations for deploying ClawdBot with security best practices, including multi-stage builds, network isolation, resource limits, and security scanning.

---

## Contents

```
scripts/hardening/docker/
├── docker-compose.yml              # Orchestration with security hardening
├── Dockerfile.hardened             # Multi-stage secure builds
├── .dockerignore                   # Build context security
├── seccomp-profiles/
│   └── clawdbot.json              # Seccomp security profile
├── entrypoint-gateway.sh          # Gateway startup script
├── entrypoint-agent.sh            # Agent startup script
└── README.md                       # This file
```

---

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB+ available memory
- 10GB+ available disk space

### Basic Setup

```bash
# 1. Clone repository
git clone https://github.com/YOUR-ORG/clawdbot-security-playbook
cd clawdbot-security-playbook/scripts/hardening/docker

# 2. Create secrets directory
mkdir -p secrets
echo "sk-ant-your-key" > secrets/anthropic_api_key.txt
echo "sk-your-key" > secrets/openai_api_key.txt
echo "$(openssl rand -hex 32)" > secrets/gateway_secret_key.txt
echo "$(openssl rand -hex 32)" > secrets/agent_auth_token.txt
echo "$(openssl rand -hex 16)" > secrets/postgres_password.txt

# 3. Set permissions
chmod 600 secrets/*.txt

# 4. Create data directories
mkdir -p data/{redis,postgres,prometheus,grafana}

# 5. Start services
docker-compose up -d

# 6. Check status
docker-compose ps
docker-compose logs -f clawdbot-gateway
```

---

## Architecture

### Service Overview

| Service | Purpose | Network | Resources |
|---------|---------|---------|-----------|
| **clawdbot-gateway** | API Gateway | frontend, backend, monitoring | 2 CPU, 2GB RAM |
| **clawdbot-agent** | Worker agents (scalable) | backend, monitoring | 1.5 CPU, 1.5GB RAM |
| **redis** | Caching layer | backend | 0.5 CPU, 512MB RAM |
| **postgres** | Database | backend | 1 CPU, 1GB RAM |
| **prometheus** | Metrics collection | monitoring | 0.5 CPU, 512MB RAM |
| **grafana** | Visualization | monitoring, frontend | 0.5 CPU, 512MB RAM |
| **trivy** | Security scanning | monitoring | 1 CPU, 1GB RAM |

### Network Architecture

```
                    ┌─────────────────┐
                    │   Internet      │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Frontend Net   │  (172.20.0.0/24)
                    │  External       │
                    └────┬───────┬────┘
                         │       │
                    ┌────▼──┐ ┌──▼────┐
                    │Gateway│ │Grafana│
                    └───┬───┘ └───────┘
                        │
                    ┌───▼───────────┐
                    │  Backend Net  │  (172.21.0.0/24)
                    │  Internal     │  (no external access)
                    └──┬──┬──┬──┬──┘
                       │  │  │  │
                ┌──────▼┐ │  │  │
                │ Agent │ │  │  │
                └───────┘ │  │  │
                   ┌──────▼┐ │  │
                   │ Redis │ │  │
                   └───────┘ │  │
                      ┌──────▼┐ │
                      │Postgres│ │
                      └────────┘ │
                                 │
                    ┌────────────▼──┐
                    │ Monitoring Net│  (172.22.0.0/24)
                    │ Metrics only  │
                    └───────────────┘
```

---

## Security Features

### 1. Network Isolation

```yaml
networks:
  frontend:    # External access (gateway, grafana)
  backend:     # Internal only (database, cache, agents)
  monitoring:  # Metrics collection (prometheus)
```

**Benefits:**
- Backend services have no direct internet access
- Monitoring traffic isolated from application traffic
- Defense in depth against network-based attacks

### 2. Resource Limits

```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'      # Prevent CPU exhaustion
      memory: 2G       # Prevent memory exhaustion
      pids: 100        # Prevent fork bombs
```

**Benefits:**
- Prevents DoS through resource exhaustion
- Fair resource allocation
- Predictable performance

### 3. Filesystem Security

```yaml
read_only: true           # Immutable root filesystem
tmpfs:
  - /tmp:rw,noexec,nosuid  # Temporary writable space
```

**Benefits:**
- Prevents tampering with container filesystem
- Limits malware execution
- Easy detection of anomalies

### 4. User Security

```yaml
user: "1000:1000"         # Non-root user
cap_drop:
  - ALL                   # Drop all capabilities
security_opt:
  - no-new-privileges:true
```

**Benefits:**
- Minimizes privilege escalation risks
- Follows principle of least privilege
- Reduces impact of container escape

### 5. Secrets Management

```yaml
secrets:
  anthropic_api_key:
    file: ./secrets/anthropic_api_key.txt
```

**Benefits:**
- Secrets not in environment variables
- Not committed to version control
- Encrypted in Docker Swarm mode

### 6. Health Checks

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "https://localhost:8443/health"]
  interval: 30s
  timeout: 10s
  retries: 3
```

**Benefits:**
- Automatic detection of unhealthy containers
- Automatic restart on failure
- Better monitoring and alerting

---

## Multi-Stage Build

### Build Stages

The `Dockerfile.hardened` uses 8 stages for maximum security and efficiency:

```
┌─────────────────┐
│ 1. base-builder │  Install build dependencies
└────────┬────────┘
         │
┌────────▼─────────────┐
│ 2. dependency-builder│  Install Python packages
└────────┬─────────────┘
         │
┌────────▼──────────┐
│ 3. app-builder    │  Build application
└────────┬──────────┘
         │
┌────────▼──────┐
│ 4. scanner    │  Scan for vulnerabilities
└───────────────┘
         │
┌────────▼──────────┐
│ 5. runtime-base   │  Minimal runtime image
└───┬───────────┬───┘
    │           │
┌───▼──────┐ ┌──▼─────┐
│6. gateway│ │7. agent│  Production images
└──────────┘ └────────┘
    │
┌───▼──────────┐
│8. development│  Dev image (optional)
└──────────────┘
```

### Build Examples

```bash
# Gateway production build
docker build \
  --target gateway \
  --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  --build-arg VERSION=1.0.0 \
  --tag clawdbot/gateway:1.0.0 \
  --tag clawdbot/gateway:latest \
  --file Dockerfile.hardened \
  .

# Agent production build
docker build \
  --target agent \
  --tag clawdbot/agent:1.0.0 \
  --file Dockerfile.hardened \
  .

# Build with security scanning
docker build \
  --target scanner \
  --tag clawdbot/gateway:scan \
  --file Dockerfile.hardened \
  .

# Development build
docker build \
  --target development \
  --tag clawdbot/dev:latest \
  --file Dockerfile.hardened \
  .
```

---

## Security Scanning

### Built-in Scanning

The Dockerfile includes a scanner stage that runs Trivy automatically:

```dockerfile
FROM aquasec/trivy:latest AS scanner
RUN trivy filesystem --severity HIGH,CRITICAL /scan
RUN trivy filesystem --format cyclonedx --output /scan/sbom.json /scan
```

### Manual Scanning

```bash
# Scan image for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image clawdbot/gateway:latest

# Scan with specific severity
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --severity HIGH,CRITICAL clawdbot/gateway:latest

# Generate SBOM
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --format cyclonedx --output sbom.json clawdbot/gateway:latest

# Scan filesystem
docker run --rm -v $(pwd):/scan aquasec/trivy filesystem /scan

# CI/CD integration (fail on HIGH/CRITICAL)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --exit-code 1 --severity HIGH,CRITICAL clawdbot/gateway:latest
```

---

## Usage

### Starting Services

```bash
# Start all services
docker-compose up -d

# Start specific service
docker-compose up -d clawdbot-gateway

# Scale agent workers
docker-compose up -d --scale clawdbot-agent=3

# View logs
docker-compose logs -f
docker-compose logs -f clawdbot-gateway

# Check service health
docker-compose ps
```

### Stopping Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: data loss)
docker-compose down -v

# Stop specific service
docker-compose stop clawdbot-gateway
```

### Managing Secrets

```bash
# Create new secret
echo "new-secret-value" > secrets/new_secret.txt
chmod 600 secrets/new_secret.txt

# Rotate secrets
echo "new-api-key" > secrets/anthropic_api_key.txt
docker-compose up -d --force-recreate clawdbot-gateway

# View secret (requires root access to container)
docker-compose exec clawdbot-gateway cat /run/secrets/anthropic_api_key
```

### Monitoring

```bash
# Access Prometheus
open http://localhost:9091

# Access Grafana
open http://localhost:3000
# Default credentials: admin / ${GRAFANA_PASSWORD}

# View metrics
curl http://localhost:9090/metrics

# Check health endpoints
curl https://localhost:8443/health
```

---

## Configuration

### Environment Variables

Create a `.env` file:

```bash
# ClawdBot Configuration
CLAWDBOT_VERSION=latest
ENVIRONMENT=production
LOG_LEVEL=INFO

# Data Directory
DATA_DIR=./data

# Redis
REDIS_PASSWORD=your-redis-password

# Grafana
GRAFANA_USER=admin
GRAFANA_PASSWORD=your-grafana-password

# Build Arguments
BUILD_DATE=2026-02-14T12:00:00Z
VCS_REF=abc1234
VERSION=1.0.0
```

### Custom Configuration Files

```bash
# Gateway configuration
cat > config/gateway.yml << 'EOF'
server:
  host: 0.0.0.0
  port: 8443

security:
  max_request_size: 10MB
  rate_limiting:
    enabled: true
    requests_per_minute: 100
EOF

# Agent configuration
cat > config/agent.yml << 'EOF'
agent:
  max_concurrent_tasks: 5
  task_timeout: 300

gateway:
  url: https://clawdbot-gateway:8443
  auth_token_file: /run/secrets/agent_auth_token
EOF
```

---

## Maintenance

### Updating Images

```bash
# Pull latest images
docker-compose pull

# Rebuild custom images
docker-compose build --pull

# Restart with new images
docker-compose up -d --force-recreate
```

### Backups

```bash
# Backup PostgreSQL
docker-compose exec postgres pg_dump -U clawdbot clawdbot > backup-$(date +%Y%m%d).sql

# Backup Redis
docker-compose exec redis redis-cli --rdb /data/dump.rdb
docker cp clawdbot-redis:/data/dump.rdb ./backup-redis-$(date +%Y%m%d).rdb

# Backup all data volumes
tar czf backup-data-$(date +%Y%m%d).tar.gz data/
```

### Restoring Backups

```bash
# Restore PostgreSQL
docker-compose exec -T postgres psql -U clawdbot clawdbot < backup-20260214.sql

# Restore Redis
docker cp backup-redis-20260214.rdb clawdbot-redis:/data/dump.rdb
docker-compose restart redis
```

### Logs Management

```bash
# View logs
docker-compose logs --tail=100 -f

# Save logs to file
docker-compose logs > logs-$(date +%Y%m%d).txt

# Clear logs (rotate)
docker-compose down
rm -rf $(docker inspect clawdbot-gateway | jq -r '.[0].LogPath')
docker-compose up -d
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose logs clawdbot-gateway

# Check health status
docker-compose ps

# Recreate service
docker-compose up -d --force-recreate clawdbot-gateway

# Check resource usage
docker stats
```

### Network Issues

```bash
# Inspect networks
docker network ls
docker network inspect clawdbot-backend

# Test connectivity
docker-compose exec clawdbot-gateway ping postgres
docker-compose exec clawdbot-agent curl https://clawdbot-gateway:8443/health
```

### Permission Issues

```bash
# Check file permissions
ls -la secrets/
ls -la data/

# Fix permissions
chmod 600 secrets/*.txt
chown -R 1000:1000 data/

# Check container user
docker-compose exec clawdbot-gateway id
```

### High Resource Usage

```bash
# Check resource usage
docker stats

# View limits
docker inspect clawdbot-gateway | jq '.[0].HostConfig.Memory'

# Adjust limits in docker-compose.yml
# Then restart:
docker-compose up -d --force-recreate
```

---

## Best Practices

### 1. Secret Management

- ✅ Store secrets in files, not environment variables
- ✅ Use `.gitignore` to prevent committing secrets
- ✅ Rotate secrets regularly
- ✅ Use Docker secrets in production
- ✅ Consider HashiCorp Vault for enterprise

### 2. Image Security

- ✅ Use minimal base images (Alpine)
- ✅ Scan images regularly with Trivy
- ✅ Pin versions for reproducibility
- ✅ Sign images with Cosign
- ✅ Use private registries

### 3. Network Security

- ✅ Use internal networks for backend services
- ✅ Expose only necessary ports
- ✅ Use TLS for all external communication
- ✅ Implement network policies in Kubernetes

### 4. Monitoring

- ✅ Set up alerts in Prometheus
- ✅ Create dashboards in Grafana
- ✅ Monitor resource usage
- ✅ Track error rates
- ✅ Set up log aggregation

### 5. Updates

- ✅ Keep base images updated
- ✅ Update dependencies regularly
- ✅ Test updates in staging first
- ✅ Have rollback plan ready
- ✅ Monitor after updates

---

## Production Deployment

### Docker Swarm

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml clawdbot

# Check services
docker service ls
docker service logs clawdbot_clawdbot-gateway
```

### Kubernetes

```bash
# Convert to Kubernetes manifests
kompose convert -f docker-compose.yml

# Apply manifests
kubectl apply -f clawdbot-gateway-deployment.yaml
kubectl apply -f clawdbot-gateway-service.yaml

# Check status
kubectl get pods
kubectl logs -f deployment/clawdbot-gateway
```

---

## Security Checklist

- [ ] Secrets stored in files, not environment variables
- [ ] All services run as non-root users
- [ ] Read-only root filesystems enabled
- [ ] Resource limits configured
- [ ] Health checks implemented
- [ ] Networks properly isolated
- [ ] Security profiles (seccomp) applied
- [ ] Capabilities minimized
- [ ] Images scanned for vulnerabilities
- [ ] Logs configured with rotation
- [ ] Backups automated
- [ ] Monitoring and alerting set up
- [ ] Incident response plan documented

---

## References

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [ClawdBot Security Playbook](../../docs/guides/05-agent-sandboxing.md)

---

**Version:** 1.0.0  
**Last Updated:** February 14, 2026  
**Maintained by:** ClawdBot Security Team
