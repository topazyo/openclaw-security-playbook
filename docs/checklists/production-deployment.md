# Production Deployment Checklist

**Document Type**: Pre-Production Gate  
**Version**: 1.0.0  
**Last Updated**: 2026-02-14  
**Owner**: DevOps + Security Team

This checklist MUST be completed and approved before ANY production deployment of ClawdBot/OpenClaw.

---

## Deployment Information

**Change Request ID**: ______________________________ (JIRA: CHG-YYYY-NNN)  
**Deployment Date/Time**: ______________________________ (must be in maintenance window)  
**Deployed By**: ______________________________ (name and email)  
**Deployment Type**: [ ] New Installation [ ] Upgrade [ ] Configuration Change [ ] Hotfix  
**Git Commit/Tag**: ______________________________ (e.g., `v1.2.3` or `abc123def`)  
**Risk Level**: [ ] Low [ ] Medium [ ] High [ ] Critical

**Maintenance Window**: From ____________ To ____________ (UTC)  
**Estimated Downtime**: ____________ minutes  
**Customer Impact**: [ ] None [ ] Degraded Performance [ ] Full Outage

---

## 1. Pre-Deployment: Planning

### 1.1 Change Management
- [ ] **Change Advisory Board (CAB) approval** obtained (for Medium/High/Critical changes)
- [ ] **Stakeholders notified** (Engineering, Operations, Customer Success)
- [ ] **Maintenance window scheduled** (off-peak hours preferred)
- [ ] **Status page updated** (if customer-impacting)
- [ ] **Rollback plan documented** (see Section 9)

**CAB Meeting Notes**: ______________________________

---

### 1.2 Architecture Review
- [ ] **Architecture diagram reviewed** (see [Security Layers](../architecture/security-layers.md))
- [ ] **Threat model assessed** (see [Threat Model](../architecture/threat-model.md))
- [ ] **No architectural anti-patterns** (public exposure, plaintext credentials, running as root)

**Architect Sign-Off**: ______________________________ Date: ______

---

## 2. Security Requirements

### 2.1 Credential Security
- [ ] **All API keys in OS keychain** (NO plaintext in configs)
- [ ] **Credentials rotated** within last 90 days
- [ ] **No secrets in Git history** (verified: `git secrets --scan`)
- [ ] **Backup credentials secured** (encrypted, separate from regular backups)

**Verification**:
```bash
./scripts/verification/verify_openclaw_security.sh | grep "Credential"
# Expected: ✅ Credential isolation: PASS
```

**Security Lead Sign-Off**: ______________________________ Date: ______

---

### 2.2 Network Security
- [ ] **Gateway binds to localhost** (`127.0.0.1:18789`, NOT `0.0.0.0`)
- [ ] **VPN required for access** (Tailscale/WireGuard configured and tested)
- [ ] **Firewall rules applied** (block public internet, allow VPN only)
- [ ] **TLS 1.2+ enforced** (strong ciphers, valid certificates)

**Network Engineer Sign-Off**: ______________________________ Date: ______

---

### 2.3 Runtime Sandboxing
- [ ] **Container runs as non-root** (`user: "1000:1000"`)
- [ ] **Capabilities dropped** (`cap_drop: [ALL]`)
- [ ] **Read-only filesystem** (`read_only: true` with tmpfs mounts)
- [ ] **Seccomp profile applied** (see [clawdbot.json](../../scripts/hardening/docker/seccomp-profiles/clawdbot.json))
- [ ] **Resource limits configured** (CPU: 2 cores, Memory: 4GB, PIDs: 200)

---

### 2.4 Supply Chain Security
- [ ] **Container image scanned** (Trivy: 0 critical, <5 high vulnerabilities)
- [ ] **Image pinned by digest** (`openclaw/clawdbot:1.2.3@sha256:abc123...`)
- [ ] **SBOM generated and reviewed** (Syft output attached)
- [ ] **Dependencies audited** (`pip-audit`, `npm audit`: 0 critical)
- [ ] **Skills on allowlist** (no unapproved skills installed)
- [ ] **Signature verification enabled** (`requireSignature: true`)

**Vulnerability Scan Results**: Attached [ ] or Link: ______________________________

---

## 3. Code Quality

### 3.1 Code Review
- [ ] **Peer review completed** (minimum 2 reviewers for production code)
- [ ] **Security review completed** (Security Team approval for high-risk changes)
- [ ] **No outstanding "FIXME" or "TODO" for critical code paths**
- [ ] **Code coverage** ≥80% (unit tests + integration tests)

**GitHub PR**: ______________________________ (link to pull request)  
**Reviewers**: ______________________________, ______________________________

---

### 3.2 Testing
- [ ] **Unit tests passed** (100% in critical modules)
- [ ] **Integration tests passed** (all 247 tests green)
- [ ] **Smoke tests passed** (critical user flows verified)
- [ ] **Load tests passed** (if performance-sensitive change)
- [ ] **Security regression tests passed** (exploit tests fail as expected)

**Test Results**: Attached [ ] or CI/CD Link: ______________________________

---

## 4. Configuration Management

### 4.1 Infrastructure as Code
- [ ] **All configs in Git** (version controlled)
- [ ] **Config reviewed** (peer review of docker-compose.yml / K8s manifests)
- [ ] **Secrets NOT in Git** (verified with `git secrets --scan`)
- [ ] **Configuration drift check** passed (staging matches production baseline)

---

### 4.2 Environment Consistency
- [ ] **Tested in staging** (identical configuration to production)
- [ ] **Staging deployment successful** (no errors)
- [ ] **Canary deployment** completed (10% traffic for 2 hours, no issues)
- [ ] **Smoke tests passed in staging** (all critical paths working)

**Staging Deployment Date**: ______________________________ (must be ≥48 hours before production)

---

## 5. Backup and Recovery

### 5.1 Pre-Deployment Backup
- [ ] **Full backup created** (timestamped: `backup-YYYY-MM-DD-pre-deployment`)
- [ ] **Backup verified** (restore tested in staging)
- [ ] **Backup integrity checked** (checksums match)
- [ ] **Backup stored off-site** (secondary region)

**Backup ID**: ______________________________ (e.g., `backup-2026-02-14-pre-v1.3.0`)

**Verification**:
```bash
./configs/examples/backup-restore.sh verify --backup-id backup-2026-02-14-pre-v1.3.0
# Expected: ✅ All checksums match
```

---

### 5.2 Rollback Plan
- [ ] **Rollback procedure documented** (see Section 9)
- [ ] **Rollback tested** (in staging, can revert within 15 minutes)
- [ ] **Previous version available** (Docker image tagged `previous-stable`)
- [ ] **Database migration reversible** (downgrade script tested, if applicable)

**Rollback RTO**: ____________ minutes (should be <15 min)

---

## 6. Monitoring and Observability

### 6.1 Monitoring Setup
- [ ] **Health checks configured** (`/health` endpoint returns 200)
- [ ] **Metrics exported** (Prometheus/Grafana dashboard)
- [ ] **Alerts configured** (PagerDuty for P0/P1 issues)
- [ ] **Log aggregation** enabled (SIEM integration or ELK stack)

---

### 6.2 Alerting Thresholds
- [ ] **Critical alerts defined** (downtime, authentication failures, security incidents)
- [ ] **Alert recipients configured** (on-call engineer, Security Team)
- [ ] **Alert escalation** configured (15 min → page on-call, 1 hour → page CISO)
- [ ] **Alert runbooks linked** (alerts include link to incident playbook)

**Grafana Dashboard**: ______________________________ (link)  
**PagerDuty Service**: ______________________________ (service ID)

---

## 7. Compliance

### 7.1 SOC 2 Type II
- [ ] **Change logged** (audit trail in JIRA)
- [ ] **Approvals documented** (CAB minutes, sign-offs)
- [ ] **Security controls validated** (CC7.2, CC8.1)
- [ ] **Incident response readiness** (can respond to P0 within 15 minutes)

---

### 7.2 ISO 27001:2022
- [ ] **Risk assessment updated** (if architectural change)
- [ ] **Security controls applied** per Annex A
- [ ] **Documentation updated** (runbooks, architecture diagrams)

---

### 7.3 GDPR
- [ ] **Data protection impact assessment** (if processing new PII)
- [ ] **PII redaction enabled** (openclaw-shield configured)
- [ ] **Breach notification process** ready (72-hour SLA)

**Compliance Officer Sign-Off**: ______________________________ Date: ______

---

## 8. Deployment Execution

### 8.1 Pre-Flight Checks
- [ ] **Team assembled** (Deployer, On-Call Engineer, Security Analyst)
- [ ] **Communication channels open** (Slack #deployments, Zoom bridge)
- [ ] **Rollback triggers defined** (error rate >5%, latency >1s, critical alert)
- [ ] **Customer notification sent** (if downtime expected)

**Deployed By**: ______________________________ (primary)  
**Backup**: ______________________________ (can execute rollback if needed)

---

### 8.2 Deployment Steps

#### Step 1: Enable Maintenance Mode
```bash
# Update status page
./scripts/deployment/status-page.sh --message "Planned maintenance in progress" --status degraded

# Drain traffic (if zero-downtime not possible)
kubectl scale deployment clawdbot --replicas=0
```
- [ ] **Completed at**: ____________ (UTC)

---

#### Step 2: Deploy New Version
```bash
# Deploy with Kubernetes
kubectl apply -f configs/examples/production-k8s.yml

# Or Docker Compose
docker-compose -f configs/examples/docker-compose-full-stack.yml up -d

# Wait for rollout
kubectl rollout status deployment/clawdbot
```
- [ ] **Completed at**: ____________ (UTC)

---

#### Step 3: Health Check
```bash
# Wait for healthy status
./scripts/verification/wait-for-healthy.sh --timeout 300

# Run smoke tests
./scripts/testing/smoke-tests.sh
```
- [ ] **Health checks passing**: ____________ (UTC)
- [ ] **Smoke tests passed**: ____________ (UTC)

---

#### Step 4: Canary Deployment
```bash
# Route 10% of traffic to new version
kubectl set image deployment/clawdbot clawdbot=openclaw/clawdbot:1.2.3 --record
kubectl patch deployment clawdbot -p '{"spec":{"strategy":{"rollingUpdate":{"maxSurge":1,"maxUnavailable":0}}}}'
```
- [ ] **10% traffic at**: ____________ (UTC)
- [ ] **Monitor for 30 minutes**: No errors, latency <100ms, no alerts ✅
- [ ] **50% traffic at**: ____________ (UTC)
- [ ] **Monitor for 30 minutes**: No errors, latency <100ms, no alerts ✅
- [ ] **100% traffic at**: ____________ (UTC)

---

#### Step 5: Post-Deployment Validation
```bash
# Full security verification
./scripts/verification/verify_openclaw_security.sh
# Expected: 0 critical findings

# Integration tests (production smoke tests)
./scripts/testing/run-integration-tests.sh --env production --suite smoke
```
- [ ] **Security verification passed**: ____________ (UTC)
- [ ] **Integration tests passed**: ____________ (UTC)

---

#### Step 6: Disable Maintenance Mode
```bash
# Update status page
./scripts/deployment/status-page.sh --message "All systems operational" --status operational
```
- [ ] **Completed at**: ____________ (UTC)

---

### 8.3 Post-Deployment Monitoring

**Monitoring Window**: 2 hours post-deployment

Monitor for:
- [ ] **Error rate**: <1% (normal baseline)
- [ ] **Latency**: p95 <100ms (normal baseline)
- [ ] **CPU/Memory**: Within limits (no spikes)
- [ ] **Security alerts**: None (no new anomalies)

**Check at**: 
- T+15min: ____________
- T+30min: ____________
- T+1h: ____________
- T+2h: ____________

**All Metrics Normal**: [ ] Yes [ ] No (if No, see Rollback section)

---

## 9. Rollback Plan

**Trigger Rollback If**:
- Error rate >5% sustained for 10 minutes
- Latency p95 >1 second sustained for 10 minutes
- Critical security alert (P0 incident)
- Data corruption detected
- Manual decision by On-Call Engineer or CISO

### Rollback Steps

#### Step 1: Revert to Previous Version
```bash
# Kubernetes rollback
kubectl rollout undo deployment/clawdbot

# Or Docker Compose (with previous-stable tag)
docker-compose -f configs/examples/docker-compose-full-stack.yml down
docker pull openclaw/clawdbot:previous-stable
docker-compose -f configs/examples/docker-compose-full-stack.yml up -d
```

#### Step 2: Restore Data (if needed)
```bash
./configs/examples/backup-restore.sh restore \
  --backup-id backup-2026-02-14-pre-v1.3.0
```

#### Step 3: Verify Rollback
```bash
./scripts/verification/verify_openclaw_security.sh
./scripts/testing/smoke-tests.sh
```

**Rollback RTO Target**: 15 minutes  
**Rollback Tested in Staging**: [ ] Yes [ ] No

---

## 10. Post-Deployment

### 10.1 Documentation
- [ ] **CHANGELOG.md updated** (version, date, changes, security implications)
- [ ] **Architecture diagrams updated** (if architectural change)
- [ ] **Runbooks updated** (if operational procedures changed)
- [ ] **Known issues documented** (in JIRA, link: ______________________________)

---

### 10.2 Communication
- [ ] **Deployment announcement** (Slack #engineering, email to stakeholders)
- [ ] **Customer notification** (if user-facing changes, link: ______________________________)
- [ ] **Status page updated** (all systems operational)

**Announcement Template**:
```
Subject: Production Deployment Complete - ClawdBot v1.2.3

The production deployment completed successfully at [TIME] UTC.

Changes:
- [Feature 1]
- [Bug Fix 1]
- [Security Update 1]

Impact: None (zero-downtime deployment)

Rollback Plan: Available if needed (RTO: 15 minutes)

Questions: Contact #deployments or ops-oncall@company.com
```

---

### 10.3 Post-Deployment Review (Within 48 Hours)
- [ ] **Deployment retrospective scheduled** (attendees: Deployer, On-Call, Security, Manager)
- [ ] **Metrics reviewed** (error rate, latency, deployment time)
- [ ] **Lessons learned documented** (what went well, what went poorly)
- [ ] **Action items created** (JIRA tickets for improvements)

**Retrospective Date/Time**: ______________________________

---

## 11. Sign-Off

### Engineering Sign-Off
**I certify that this deployment meets all technical requirements and has been tested.**

Engineer Name: ______________________________  
Signature: ______________________________  
Date: ______________________________

---

### Security Sign-Off
**I certify that this deployment meets all security requirements and poses acceptable risk.**

Security Team Member: ______________________________  
Signature: ______________________________  
Date: ______________________________

---

### Operations Sign-Off
**I certify that monitoring, backups, and rollback procedures are in place.**

Operations Lead: ______________________________  
Signature: ______________________________  
Date: ______________________________

---

### Management Approval (High/Critical Risk Only)
**I approve this deployment to production.**

Engineering Manager / CTO: ______________________________  
Signature: ______________________________  
Date: ______________________________

---

## 12. Post-Deployment Status

**Deployment Status**: [ ] SUCCESS [ ] ROLLED BACK [ ] FAILED

**Actual Downtime**: ____________ minutes (Expected: ____________)  
**Issues Encountered**: ______________________________  
**Resolution**: ______________________________

**Final Verification**:
```bash
./scripts/verification/verify_openclaw_security.sh
# Result: [PASS / FAIL]
```

**Deployed Version**: ______________________________ (Git tag or SHA)  
**Deployment Completed At**: ______________________________ (UTC)

---

**Related Documentation**:
- [Security Review Checklist](./security-review.md) - Pre-deployment security gate
- [Onboarding Checklist](./onboarding-checklist.md) - For new team members
- [Quick Start Guide](../guides/01-quick-start.md) - Initial setup
- [Incident Response Procedure](../procedures/incident-response.md) - If deployment fails
- [Backup and Recovery Procedure](../procedures/backup-recovery.md) - Rollback procedures

**Document Owner**: DevOps + Security Team  
**Last Updated**: 2026-02-14  
**Next Review**: 2026-05-14 (quarterly)  
**Questions**: devops@company.com, security@company.com
