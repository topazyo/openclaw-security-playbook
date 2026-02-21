# Incident Response Playbook: Malicious Skill Compromise

**Playbook ID**: IRP-003  
**Severity**: P0 - Critical  
**Estimated Response Time**: 20 minutes (initial containment) + 8 hours (full response)  
**Last Updated**: 2026-02-14  
**Owner**: Security Operations Team

---

## Table of Contents

1. [Overview](#overview)
2. [Related Documents](#related-documents)
3. [Detection Indicators](#detection-indicators)
4. [Triage & Assessment](#triage--assessment)
5. [Containment](#containment)
6. [Eradication](#eradication)
7. [Recovery](#recovery)
8. [Post-Incident Review](#post-incident-review)
9. [Appendix](#appendix)

---

## Overview

### Purpose
This playbook provides step-by-step procedures for responding to supply chain attacks involving malicious or compromised OpenClaw/ClawdBot skills, including backdoored npm packages, typosquatting attacks, and dependency confusion.

### Scope
- **Attack types**: Malicious skill installation, skill compromise post-install, dependency confusion, typosquatting, backdoored npm packages
- **Attack vectors**: npm registry poisoning, GitHub repository compromise, social engineering, abandoned package takeover
- **Systems covered**: Skill registry, npm packages, agent skill execution environment, supply chain integrity checks

### Success Criteria
- ✅ Malicious skill blocked and removed within 20 minutes
- ✅ Affected agents identified and quarantined
- ✅ Skill allowlist updated to prevent reinstallation
- ✅ No data exfiltration or lateral movement
- ✅ Supply chain security controls enhanced within 8 hours

---

## Related Documents

### Policies & Procedures
- **[SEC-004 Incident Response Policy](../../docs/policies/incident-response-policy.md)** - Incident classification and escalation
- **[SEC-002 Access Control Policy](../../docs/policies/access-control-policy.md)** - Skill permission model
- **[Incident Response Procedure](../../docs/procedures/incident-response.md)** - 5-phase IR framework
- **[Vulnerability Management Procedure](../../docs/procedures/vulnerability-management.md)** - Dependency scanning and patching

### Attack Scenarios
- **[Scenario 002: Malicious Skill Deployment](../scenarios/scenario-002-malicious-skill-deployment.md)** - Typosquatting attack via npm
- **[Scenario 002: Malicious Skill Deployment](../scenarios/scenario-002-malicious-skill-deployment.md)** - npm package poisoning, dependency confusion

### Technical References
- **[Supply Chain Security Guide](../../docs/guides/05-supply-chain-security.md)** - Layer 5: Skill integrity, manifest validation, SBOM generation
- **[Skill Manifest Tool](../../scripts/supply-chain/skill_manifest.py)** - Integrity verification and dangerous pattern detection
- **[Skill Integrity Monitor](../../scripts/supply-chain/skill_integrity_monitor.sh)** - Continuous monitoring for skill changes
- **[Community Tools - openclaw-detect](../../docs/guides/07-community-tools-integration.md#openclaw-detect)** - Shadow AI detection, unapproved skill discovery

---

## Detection Indicators

### High-Confidence Indicators (Immediate Response)

1. **openclaw-detect Shadow AI Alerts**
   
   openclaw-detect identifies unapproved skills executing on agents via EDR/file monitoring.
   
   **Example Alert**:
   ```json
   {
     "timestamp": "2026-02-14T14:22:30Z",
     "alert_type": "unauthorized_skill_detected",
     "severity": "critical",
     "agent_id": "agent-prod-12",
     "skill_name": "@attacker/credential-stealer",
     "skill_version": "1.2.3",
     "installation_source": "npm",
     "approved_in_allowlist": false,
     "risk_score": 0.96,
     "indicators": [
       "Network connections to attacker.com",
       "Filesystem access outside workspace",
       "Credential vault access attempted"
     ]
   }
   ```

2. **Skill Integrity Verification Failure**
   
   ```bash
   # Daily automated integrity check
   ./scripts/supply-chain/skill_manifest.py \
     --skills-dir ~/.openclaw/skills \
     --verify-signatures \
     --check-integrity
   ```
   
   **Example Output**:
   ```
   ❌ FAIL: @attacker/credential-stealer@1.2.3
      - Signature verification: FAILED (no valid GPG signature)
      - Hash mismatch: expected sha256:abc123..., got sha256:def456...
      - npm audit: 1 critical vulnerability (Command Injection CVE-2024-12345)
      - Dangerous patterns detected: os.system(), eval(), subprocess.Popen()
   ```

3. **Anomalous Skill Behavior** (openclaw-telemetry)
   
   ```json
   {
     "timestamp": "2026-02-14T14:25:15Z",
     "alert_type": "skill_behavioral_anomaly",
     "severity": "high",
     "agent_id": "agent-prod-12",
     "skill_name": "@attacker/credential-stealer",
     "anomaly_details": {
       "network_connections": {
         "baseline": 0,
         "current": 47,
         "destinations": ["https://attacker.com/collect", "https://evil.ru/exfil"]
       },
       "filesystem_access": {
         "baseline_paths": ["/tmp/workspace"],
         "current_paths": ["~/.ssh", "~/.aws", "~/.openclaw/credentials"]
       },
       "execution_frequency": {
         "baseline_calls_per_hour": 2.3,
         "current_calls_per_hour": 234.7,
         "deviation_sigma": 18.2
       }
     },
     "anomaly_score": 0.93
   }
   ```

4. **Supply Chain Poisoning Indicators**
   
   **Typosquatting Detection**:
   ```bash
   # Check for typosquatted package names
   npm list --depth=0 | grep -E "(cluadbot|openclwa|antrhropic)"
   # Should return empty if no typosquatting
   ```
   
   **Dependency Confusion**:
   ```bash
   # Check for internal packages resolved from public registry
   npm ls @openclaw/internal-skill 2>&1 | grep -i "external registry"
   ```
   
   **Sudden Ownership Transfer**:
   ```bash
   # Check npm package maintainers
   npm view @attacker/credential-stealer maintainers
   # Compare with previous snapshot
   ```

### Medium-Confidence Indicators (Investigate)

5. **GitHub Repository Compromise**
   
  - Skill's GitHub repository shows suspicious commits (credential exfiltration, obfuscated code)
   - Repository suddenly transferred to new owner
   - Recent commits from unknown committers without PR review
   
   ```bash
   # Check skill repository for suspicious activity
   git clone https://github.com/attacker/credential-stealer.git
   cd credential-stealer
   
   # Review recent commits
   git log --since="7 days ago" --pretty=format:"%h %an %ae %s"
   
   # Look for obfuscated code
   grep -r "eval\|exec\|fromCharCode" --include="*.js" .
   ```

6. **Excessive Permissions Requested**
   
   Skill manifest requests high-risk permissions without clear justification.
   
   ```yaml
   # skill-manifest.yml
   permissions:
     - keychain.read      # ⚠️ High risk: access to credentials
     - filesystem.write   # ⚠️ High risk: arbitrary file write
     - network.any        # ⚠️ High risk: bypass domain allowlist
     - process.spawn      # ⚠️ High risk: arbitrary command execution
   ```
   
   **Risk Assessment**:
   ```bash
   ./scripts/supply-chain/skill_manifest.py \
     --skill-path ~/.openclaw/skills/@attacker/credential-stealer \
     --assess-risk
   ```

7. **npm Audit Vulnerabilities**
   
   ```bash
   # Check for known vulnerabilities in skill dependencies
   cd ~/.openclaw/skills/@attacker/credential-stealer
   npm audit --json | jq '.vulnerabilities | to_entries[] | select(.value.severity == "critical")'
   ```

### Low-Confidence Indicators (Monitor)

8. **General Suspicious Characteristics**
   - Skill has very few downloads on npm (<100 total)
   - Skill repo has no stars, forks, or watchers
   - Skill maintainer account created recently (<30 days)
   - Skill description/README is minimal or copied from legitimate package
   - Skill has no test coverage or CI/CD

---

## Triage & Assessment

### Initial Assessment (5 minutes)

**Incident Commander**: On-call security analyst

1. **Confirm the Alert**
   
   ```bash
   # Check openclaw-detect for skill detections
   curl -X GET "https://detect.openclaw.ai/api/detections/recent?hours=1&type=unauthorized_skill" \
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
   
   # Query audit logs for skill installation events
   curl -X POST "https://elk.openclaw.ai/security-events-*/_search" \
     -H "Content-Type: application/json" \
     -d '{
       "query": {
         "bool": {
           "must": [
             {"term": {"event_type": "configuration_change"}},
             {"term": {"action": "skill_installed"}},
             {"range": {"timestamp": {"gte": "now-24h"}}}
           ]
         }
       },
       "sort": [{"timestamp": "desc"}]
     }' | jq '.hits.hits[]._source'
   ```

2. **Identify Affected Skill**
   
   **Skill Details**:
   - **Name**: `@attacker/credential-stealer`
   - **Version**: `1.2.3`
   - **Installation Source**: npm registry (https://registry.npmjs.org)
   - **Installation Date**: `2026-02-14T14:20:00Z`
   - **Installed By**: `alice@openclaw.ai` (social engineering victim or compromised account)
   - **Approved in Allowlist**: ❌ No

3. **Determine Scope**
   
   ```bash
   # Find all agents with malicious skill installed
   ./scripts/supply-chain/skill_integrity_monitor.sh \
     --find-skill "@attacker/credential-stealer" \
     --output affected-agents.json
   
   # Example output
   cat affected-agents.json
   {
     "skill": "@attacker/credential-stealer@1.2.3",
     "affected_agents": [
       {"agent_id": "agent-prod-12", "installation_date": "2026-02-14T14:20:00Z"},
       {"agent_id": "agent-dev-05", "installation_date": "2026-02-14T14:22:00Z"},
       {"agent_id": "agent-staging-03", "installation_date": "2026-02-14T14:25:00Z"}
     ],
     "total_affected": 3
   }
   ```

4. **Assess Attack Type**
   
   | Attack Type | Characteristics | Example |
   |-------------|-----------------|---------|
   | **Typosquatting** | Package name similar to popular skill | `@ant hropic/sdk` (vs `@anthropic/sdk`) |
   | **Dependency Confusion** | Internal package name published to public registry | `@openclaw/internal-skill` on npm (should be private) |
   | **Abandoned Package Takeover** | Legitimate but unmaintained package transferred to attacker | `popular-skill` (maintainer unresponsive for 2 years) |
   | **Backdoored Legitimate Package** | Compromised maintainer account, malicious code injected | `legitimate-skill@2.5.1` (version 2.5.0 was clean) |
   | **Social Engineering** | Attacker convinces user to install malicious skill | User searched "OpenClaw credential manager", installed attacker's fake skill |

5. **Classify Incident Severity** (SEC-004)
   
   ```
   IF (skill accessed credentials OR exfiltrated data) THEN
     severity = P0  # Critical - Active data breach
   ELSE IF (skill installed on production agents) THEN
     severity = P0  # Critical - Production impact
   ELSE IF (skill installed on dev/staging only) THEN
     severity = P1  # High - Non-production but still serious
   ELSE IF (skill detected before execution) THEN
     severity = P2  # Medium - Preventive detection
   END IF
   ```

6. **Escalate if Needed**
   - **P0**: Notify CISO, Legal, PR (within 15 minutes)
   - **P1**: Notify Security Manager (within 30 minutes)

---

## Containment

**Goal**: Stop malicious skill execution and prevent spread to other agents.  
**Time Bound**: Complete within 20 minutes for P0, 1 hour for P1.

### Phase 1: Immediate Actions (0-15 minutes)

1. **Block Skill Immediately (All Agents)**
   
   ```bash
   # Add skill to global deny list
   curl -X POST "https://gateway.openclaw.ai/skills/denylist" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "skill_name": "@attacker/credential-stealer",
       "all_versions": true,
       "reason": "Malicious skill - data exfiltration detected - IRP-003",
       "block_installation": true,
       "block_execution": true,
       "alert_on_attempt": true
     }'
   
   # Verify deny list updated
   curl -X GET "https://gateway.openclaw.ai/skills/denylist" \
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.denied_skills[] | select(.name == "@attacker/credential-stealer")'
   ```

2. **Kill Running Skill Processes**
   
   ```bash
   # For each affected agent, kill skill processes
   for agent in $(jq -r '.affected_agents[].agent_id' affected-agents.json); do
     echo "Killing malicious skill on $agent..."
     
     # Find skill process
     docker exec "$agent" ps aux | grep credential-stealer
     
     # Kill process
     docker exec "$agent" pkill -9 -f credential-stealer
     
     # Or auto-containment script
     ./scripts/incident-response/auto-containment.py \
       --action kill_skill \
       --agent-id "$agent" \
       --skill-name "@attacker/credential-stealer" \
       --reason "Malicious skill - IR P-003"
   done
   ```

3. **Isolate Affected Agents**
   
   ```bash
   # Network isolation to prevent data exfiltration
   for agent in $(jq -r '.affected_agents[].agent_id' affected-agents.json); do
     echo "Isolating agent: $agent"
     
     # Docker network disconnect
     docker network disconnect openclaw-network "$agent"
     
     # Or Kubernetes network policy
     kubectl label pod "$agent" quarantine=true
     
     # Or auto-containment script
     ./scripts/incident-response/auto-containment.py \
       --action isolate_container \
       --container-id "$agent" \
       --reason "Malicious skill detected - IRP-003"
   done
   ```

4. **Revoke Skill Permissions**
   
   ```bash
   # Remove skill from agent configurations
   for agent in $(jq -r '.affected_agents[].agent_id' affected-agents.json); do
     echo "Revoking permissions for $agent..."
     
     # Edit agent config to remove skill
     docker exec "$agent" sh -c "sed -i '/@attacker\/credential-stealer/d' /etc/openclaw/skills.conf"
     
     # Restart agent (without malicious skill)
     docker restart "$agent"
   done
   ```

5. **Block npm Package (if applicable)**
   
   ```bash
   # Contact npm security team to report malicious package
   cat > npm-security-report.txt <<EOF
   To: security@npmjs.com
   Subject: Malicious Package Report - @attacker/credential-stealer
   
   We have identified a malicious package on the npm registry:
   
   Package: @attacker/credential-stealer
   Version: 1.2.3
   Malicious Behavior:
  - Credential exfiltration via keychain access
   - Data exfiltration to https://attacker.com/collect
   - Unauthorized filesystem access
   
   Evidence: [Attach forensics data]
   
   Request: Please remove this package from npm registry immediately.
   
   Contact: security@openclaw.ai
   PGP Key: [fingerprint]
   EOF
   
   # Send report
   mail -s "Malicious Package Report" < npm-security-report.txt security@npmjs.com
   
   # Also report via npm CLI
   npm report @attacker/credential-stealer --reason malware
   ```

### Phase 2: Forensic Preservation (15-30 minutes)

6. **Collect Evidence**
   
   ```bash
   # Comprehensive forensics collection
   ./scripts/incident-response/forensics-collector.py \
     --incident-id "IRP-003-20260214" \
     --scope comprehensive \
     --targets "$(jq -r '.affected_agents[].agent_id' affected-agents.json | tr '\n' ',')" \
     --include-skill-artifacts \
     --output-dir /secure/forensics/IRP-003/ \
     --encrypt-with-key $FORENSICS_PGP_KEY
   ```
   
   **Critical Evidence**:
   - [ ] **Malicious skill package**: Full npm package tarball (`.tgz`)
   - [ ] **Skill manifest**: `package.json`, `skill-manifest.yml`, dependencies
   - [ ] **Skill source code**: All `.js`, `.ts`, `.py` files
   - [ ] **Skill execution logs**: All invocations, parameters, outputs
   - [ ] **Network traffic**: PCAP files showing connections to attacker.com
   - [ ] **Filesystem changes**: Files created, modified, or accessed by skill
   - [ ] **Audit logs**: Installation events, permission grants, user actions

7. **Preserve Skill Artifacts**
   
   ```bash
   # Extract skill package for forensic analysis
   mkdir -p /secure/forensics/IRP-003/skill-artifacts
   cd /secure/forensics/IRP-003/skill-artifacts
   
   # Copy skill from affected agent
   docker cp agent-prod-12:/root/.openclaw/skills/@attacker/credential-stealer ./
   
   # Create tarball with hashes
   tar -czf credential-stealer-1.2.3.tar.gz credential-stealer/
   sha256sum credential-stealer-1.2.3.tar.gz > credential-stealer-1.2.3.tar.gz.sha256
   
   # Also download original from npm (if still available)
   npm pack @attacker/credential-stealer@1.2.3
   sha256sum attacker-credential-stealer-1.2.3.tgz > npm-package.sha256
   ```

8. **Analyze Malicious Code**
   
   ```bash
   # Static analysis of skill code
   cd /secure/forensics/IRP-003/skill-artifacts/credential-stealer
   
   # Search for suspicious patterns
   echo "=== Dangerous function calls ==="
   grep -rn "eval\|exec\|system\|spawn\|child_process" .
   
   echo "=== Network connections ==="
   grep -rn "http\|https\|fetch\|axios\|request" . | grep -v node_modules
   
   echo "=== Filesystem access ==="
   grep -rn "readFile\|writeFile\|unlink\|rmdir" .
   
   echo "=== Credential access ==="
   grep -rn "keychain\|credential\|password\|secret\|token\|api_key" .
   
   echo "=== Obfuscated code ==="
   grep -rn "fromCharCode\|atob\|btoa\|Buffer" .
   ```

---

## Eradication

**Goal**: Remove malicious skill and prevent reinstallation.  
**Time Bound**: Complete within 8 hours for P0, 24 hours for P1.

### Root Cause Analysis

1. **Determine How Skill Was Installed**
   
   **Scenario A: User Social Engineering**
   ```bash
   # Check audit logs for user actions
   curl -X POST "https://elk.openclaw.ai/authentication-*/_search" \
     -H "Content-Type: application/json" \
     -d '{
       "query": {
         "bool": {
           "must": [
             {"term": {"user_id": "alice@openclaw.ai"}},
             {"term": {"action": "skill_installed"}},
             {"range": {"timestamp": {"gte": "2026-02-14T14:00:00Z", "lte": "2026-02-14T15:00:00Z"}}}
           ]
         }
       }
     }' | jq .
   ```
   
   **Indicators**:
   - User manually ran `npm install @attacker/credential-stealer`
   - User found skill via web search (e.g., "OpenClaw credential manager")
   - Attacker used SEO poisoning to rank malicious skill highly
   
   **Remediation**:
   - User security awareness training (phishing, typosquatting)
   - Require skill approval process (no direct npm install)
   - Implement skill repository curation (vetted skills only)
   
   ---
   
   **Scenario B: Dependency Confusion**
   ```bash
   # Check if internal package name exists on public registry
   npm view @openclaw/internal-skill
   # Should return 404 if properly scoped to private registry
   ```
   
   **Indicators**:
   - Internal package `@openclaw/internal-skill` also published to npm (higher version number)
   - npm resolved to public registry instead of private registry
   - Agent installed public package instead of internal package
   
   **Remediation**:
   - Configure `.npmrc` to scope internal packages to private registry:
   ```ini
   # .npmrc
   @openclaw:registry=https://npm.openclaw.internal/
   registry=https://registry.npmjs.org/
   ```
   - Reserve internal package names on npm (publish placeholder with warning)
   - Implement SBOM verification (compare expected vs installed packages)
   
   ---
   
   **Scenario C: Compromised npm Account**
   ```bash
   # Check if legitimate skill was backdoored
   npm view @legitimate/skill versions --json | jq .
   
   # Compare maintainers across versions
   npm view @legitimate/skill@2.5.0 maintainers
   npm view @legitimate/skill@2.5.1 maintainers  # Version 2.5.1 has new maintainer?
   ```
   
   **Indicators**:
   - Previously legitimate skill suddenly has malicious code in new version
   - Skill maintainer's npm account compromised (MFA not enabled)
   - Attacker published malicious version as patch update
   
   **Remediation**:
   - Pin skill versions in `package-lock.json` (no automatic updates)
   - Monitor skill versions for sudden changes (skill_integrity_monitor.sh)
   - Require GPG signatures for skill updates
   - Contact upstream maintainer to secure their account

2. **Update Skill Allowlist**
   
   ```bash
   # Add malicious skill to deny list permanently
   cat >> configs/skill-policies/blocklist.json <<EOF
   {
     "skill": "@attacker/credential-stealer",
     "all_versions": true,
    "reason": "Malicious skill - credential exfiltration - IRP-003",
     "date_added": "2026-02-14",
     "references": [
       "https://openclaw.ai/security/incident/IRP-003",
       "https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX"
     ]
   }
   EOF
   
   # Regenerate allowlist (remove if present)
   ./scripts/supply-chain/skill_manifest.py \
     --generate-allowlist \
     --exclude-blocklisted \
     --output configs/skill-policies/allowlist.json
   ```

3. **Implement Enhanced Supply Chain Controls**
   
   **Code Changes** (skill installation workflow):
   ```python
   # agent/skill_manager.py
   
   def install_skill(skill_name: str, skill_version: str) -> bool:
       """Install skill with enhanced security checks."""
       
       # 1. Pre-installation checks
       if not is_in_allowlist(skill_name, skill_version):
           log_security_event("skill_installation_blocked", "not in allowlist")
           raise SkillNotAllowedError(f"{skill_name}@{skill_version} not in allowlist")
       
       if is_in_denylist(skill_name):
           log_security_event("skill_installation_blocked", "in denylist")
           raise SkillDeniedError(f"{skill_name} is denied (malicious)")
       
       # 2. Typosquatting detection
       if is_typosquatting(skill_name):
           log_security_event("possible_typosquatting", skill_name)
           raise SkillSecurityError(f"Possible typosquatting: {skill_name}. Did you mean: {suggest_correct_name(skill_name)}?")
       
       # 3. Download and verify signature
       skill_package = download_skill(skill_name, skill_version)
       if not verify_gpg_signature(skill_package):
           log_security_event("skill_signature_verification_failed", skill_name)
           raise SkillSecurityError(f"GPG signature verification failed: {skill_name}")
       
       # 4. Verify package integrity (hash)
       expected_hash = get_expected_hash(skill_name, skill_version)
       actual_hash = sha256(skill_package)
       if expected_hash != actual_hash:
           log_security_event("skill_integrity_verification_failed", skill_name)
           raise SkillIntegrityError(f"Hash mismatch: expected {expected_hash}, got {actual_hash}")
       
       # 5. Static analysis (dangerous patterns)
       dangerous_patterns = scan_for_dangerous_code(skill_package)
       if dangerous_patterns:
           log_security_event("skill_dangerous_code_detected", dangerous_patterns)
           raise SkillSecurityError(f"Dangerous code detected: {dangerous_patterns}")
       
       # 6. SBOM generation and vulnerability scan
       sbom = generate_sbom(skill_package)
       vulns = scan_vulnerabilities(sbom)
       if any(v.severity == "critical" for v in vulns):
           log_security_event("skill_critical_vulnerability_detected", vulns)
           raise SkillVulnerabilityError(f"Critical vulnerabilities: {vulns}")
       
       # 7. Sandboxed test execution (dry-run)
       test_result = test_skill_in_sandbox(skill_package)
       if test_result.anomaly_score > 0.8:
           log_security_event("skill_sandbox_test_failed", test_result)
           raise SkillSecurityError(f"Skill behavior anomaly detected: {test_result.details}")
       
       # 8. Install with restricted permissions
       install_skill_sandboxed(skill_package, permissions=get_minimal_permissions(skill_name))
       
       # 9. Enable continuous monitoring
       enable_skill_monitoring(skill_name, skill_version)
       
       log_security_event("skill_installed_successfully", skill_name)
       return True
   ```

4. **Deploy Enhanced Controls**
   
   ```bash
   # Build updated agent image with enhanced skill security
   docker build -t openclaw/agent:hardened-skills-v2 \
     -f scripts/hardening/docker/Dockerfile.hardened .
   
   # Rolling update
   kubectl set image deployment/openclaw-agents \
     agent=openclaw/agent:hardened-skills-v2
   ```

---

## Recovery

**Goal**: Restore normal operations with improved supply chain security.  
**Time Bound**: Complete within 12 hours for P0, 48 hours for P1.

### Phase 1: Clean Installation (2-4 hours)

1. **Remove Malicious Skill Completely**
   
   ```bash
   # For each affected agent
   for agent in $(jq -r '.affected_agents[].agent_id' affected-agents.json); do
     echo "Cleaning agent: $agent"
     
     # Stop agent
     docker stop "$agent"
     
     # Remove skill directory
     docker exec "$agent" rm -rf /root/.openclaw/skills/@attacker/credential-stealer
     
     # Remove from package.json
     docker exec "$agent" npm uninstall @attacker/credential-stealer
     
     # Clear npm cache
     docker exec "$agent" npm cache clean --force
     
     # Verify removal
     docker exec "$agent" npm list @attacker/credential-stealer 2>&1 | grep "empty"
   done
   ```

2. **Redeploy Agents with Clean State**
   
   ```bash
   # Pull latest hardened image
   docker pull openclaw/agent:hardened-skills-v2
   
   # Redeploy each agent
   for agent in $(jq -r '.affected_agents[].agent_id' affected-agents.json); do
     echo "Redeploying agent: $agent"
     
     # Backup agent data (conversations, config)
     docker cp "$agent:/var/lib/openclaw" "/backup/$agent-data-$(date +%Y%m%d)"
     
     # Remove old container
     docker rm -f "$agent"
     
     # Deploy new container with clean image
     docker run -d \
       --name "$agent" \
       --cap-drop ALL \
       --cap-add NET_BIND_SERVICE \
       --read-only \
       --tmpfs /tmp:rw,noexec,nosuid,size=100m \
       --security-opt no-new-privileges \
       --security-opt seccomp=../../scripts/hardening/docker/seccomp-profiles/clawdbot.json \
       -v "/backup/$agent-data-$(date +%Y%m%d):/var/lib/openclaw:ro" \
       -p 127.0.0.1:18789:18789 \
       openclaw/agent:hardened-skills-v2
     
     # Verify clean state
     docker exec "$agent" sh -c "! npm list | grep -i credential-stealer"
   done
   ```

3. **Restore from Clean Backup** (if needed)
   
   ```bash
   # If agent data is suspect, restore from known-good backup
   # (Assuming daily backups per backup-recovery.md)
   
   LAST_CLEAN_BACKUP="2026-02-13"  # Day before incident
   
   for agent in $(jq -r '.affected_agents[].agent_id' affected-agents.json); do
     echo "Restoring $agent from $LAST_CLEAN_BACKUP backup"
     
     # Restore from backup
     docker cp "/backups/daily/$LAST_CLEAN_BACKUP/$agent-data.tar.gz" \
       "$agent:/var/lib/openclaw/"
     
     docker exec "$agent" sh -c "cd /var/lib/openclaw && tar -xzf $agent-data.tar.gz"
   done
   ```

4. **Verify Security Posture**
   
   ```bash
   # Run security verification on all restored agents
   for agent in $(jq -r '.affected_agents[].agent_id' affected-agents.json); do
     echo "Verifying security posture: $agent"
     
     ./scripts/verification/verify_openclaw_security.sh \
       --container "$agent" \
       --check-supply-chain \
       --verify-skills
     
     # Also verify SBOM
     ./scripts/supply-chain/skill_manifest.py \
       --agent-id "$agent" \
       --verify-all-skills \
       --require-signatures
   done
   ```

### Phase 2: Enhanced Monitoring (ongoing)

5. **Enable Continuous Skill Monitoring**
   
   ```bash
   # Start skill integrity monitor (runs every 15 minutes)
   cat > /etc/cron.d/skill-integrity-monitor <<EOF
   # IRP-003 enhanced monitoring
   */15 * * * * root /opt/openclaw/scripts/supply-chain/skill_integrity_monitor.sh --alert-on-change
   EOF
   
   # Enable openclaw-detect shadow AI detection
   curl -X PATCH "https://detect.openclaw.ai/config" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "scan_frequency_minutes": 15,
       "alert_on_unapproved_skills": true,
       "alert_threshold": "medium",
       "notification_channel": "slack_security"
     }'
   ```

6. **Implement Proactive Typosquatting Detection**
   
   ```bash
   # Create allowlist of legitimate skill names
   cat > /etc/openclaw/legitimate-skills.txt <<EOF
   @anthropic/sdk
   @openai/api
   @openclaw/official-skill
   EOF
   
   # Check for typosquatting attempts daily
   cat > /etc/cron.daily/typosquatting-scan <<'EOF'
   #!/bin/bash
   # Scan for typosquatted packages similar to legitimate skills
   
   while read legitimate_skill; do
     # Generate typosquatting variations
     # (swap characters, add/remove characters, etc.)
     variations=$(python3 -c "
   import itertools
   skill = '$legitimate_skill'
   # Generate character swap variations
   for i in range(len(skill)-1):
       print(skill[:i] + skill[i+1] + skill[i] + skill[i+2:])
   ")
     
     # Check if variations exist on npm
     for variant in $variations; do
       if npm view "$variant" > /dev/null 2>&1; then
         echo "⚠️  Possible typosquatting: $variant (legitimate: $legitimate_skill)"
         # Alert security team
         curl -X POST "https://slack.openclaw.ai/webhooks/security" \
           -d "{\"text\": \"Possible typosquatting detected: $variant\"}"
       fi
     done
   done < /etc/openclaw/legitimate-skills.txt
   EOF
   
   chmod +x /etc/cron.daily/typosquatting-scan
   ```

---

## Post-Incident Review

Use the standardized template: **[reporting-template.md](reporting-template.md)**

### Key Sections to Complete

1. **Executive Summary**
   - Malicious skill type (typosquatting / dependency confusion / compromised maintainer)
   - Number of agents affected
   - Data exfiltration status
   - Supply chain security improvements

2. **Timeline**
   ```
   2026-02-14 14:20:00 UTC - Malicious skill installed on agent-prod-12 by user alice@openclaw.ai
   2026-02-14 14:22:30 UTC - openclaw-detect identifies unauthorized skill execution
   2026-02-14 14:25:15 UTC - openclaw-telemetry detects anomalous network connections to attacker.com
   2026-02-14 14:30:00 UTC - Security analyst receives alert, begins response
   2026-02-14 14:35:00 UTC - Skill blocked globally, running processes killed (SLA: 20min, Actual: 15min) ✅
   2026-02-14 14:50:00 UTC - Affected agents isolated, forensics collection started
   2026-02-14 16:00:00 UTC - Root cause identified (typosquatting attack via npm)
   2026-02-14 20:00:00 UTC - Malicious skill reported to npm security, package removed
   2026-02-15 02:00:00 UTC - All agents redeployed with clean image, enhanced controls active
   ```

3. **Root Cause Analysis** (5 Whys)
   ```
   Problem: Malicious skill installed on production agents
   Why? → User manually installed skill without security review
   Why? → No skill approval process enforced (users can run `npm install`)
   Why? → Skill installation workflow lacks security gates
   Why? → Supply chain security requirements not defined during initial design
   Why? → Security team not involved in skill system architecture (tech debt)
   
   **Root Cause**: Lack of mandatory security review for skill installation workflow
   ```

4. **Impact Assessment**
   - **Agents Affected**: 3 agents (1 prod, 1 dev, 1 staging)
   - **Data Exfiltrated**: 14 API keys (Restricted tier), 127 conversation transcripts (Internal)
   - **Network Connections**: 47 connections to attacker.com (all blocked by network policy) ✅
   - **Downtime**: 11.5 hours (agents offline during forensics and redeployment)
   - **Credentials Rotated**: 14 API keys (within 1 hour per SEC-002)
   - **Compliance Impact**: Potential SOC 2 finding (CC9.2 - Vendor Risk), no GDPR breach notification required (credentials rotated before misuse)

5. **Defense Effectiveness**
   
   | Defense Layer | Status | Effectiveness |
   |---------------|--------|---------------|
   | **Layer 5 - Supply Chain Security** | Partial | openclaw-detect identified skill post-installation, but no pre-installation check ⚠️ |
   | **Layer 6 - Behavioral Monitoring** | Working | openclaw-telemetry detected anomaly within 5 minutes ✅ |
   | **Layer 2 - Network Segmentation** | Working | Blocked data exfiltration to attacker.com ✅ |
   | **Layer 7 - Organizational Controls** | Missing | No skill approval process, users can install arbitrary skills ❌ |
   
   **Overall Assessment**: Defense-in-depth limited impact, but pre-installation controls needed ⚠️

6. **Action Items**
   
   | # | Action Item | Owner | Due Date | Priority |
   |---|-------------|-------|----------|----------|
   | 1 | Implement mandatory skill approval workflow (no direct npm install) | Engineering | 2026-02-21 | P0 |
   | 2 | Deploy typosquatting detection in skill installation pipeline | Security | 2026-02-18 | P0 |
   | 3 | Configure private npm registry scope for internal packages (@openclaw/*) | DevOps | 2026-02-16 | P0 |
   | 4 | Require GPG signatures for all skills in allowlist | Security | 2026-03-01 | P0 |
   | 5 | Implement SBOM verification in CI/CD (detect dependency changes) | Engineering | 2026-03-15 | P1 |
   | 6 | Create skill security review checklist for approvers | Security | 2026-02-20 | P1 |
   | 7 | Report malicious npm package to npm security team | Security | 2026-02-14 | P0 (⏲️ Complete) |
   | 8 | User security awareness training (typosquatting, social engineering) | Training | 2026-03-01 | P1 |

7. **Lessons Learned**
   
   **What Went Well** ✅:
   - openclaw-detect identified unapproved skill quickly (2 minutes after execution)
   - openclaw-telemetry behavioral anomaly detection caught exfiltration attempts
   - Network segmentation prevented successful data exfiltration
   - Incident response procedures effective (contained within 15 minutes)
   
   **What Needs Improvement** ⚠️:
   - No pre-installation security checks (users can install arbitrary npm packages)
   - No skill approval workflow (organizational control missing)
   - Typosquatting detection reactive (after installation) instead of proactive
   - Internal package naming not protected against dependency confusion
   
   **Preventive Measures** 🛡️:
   - Shift security left: enforce checks at skill installation time, not execution time
   - Implement organizational policy: skill approval required for production agents
   - Proactive typosquatting monitoring: scan npm for suspicious package names weekly
   - Supply chain security as design requirement for all new features

---

## Appendix

### A. Compliance Reporting

**SOC 2 Type II** (CC9.2 - Vendor Risk Management):
- Third-party software (npm packages) assessed for security risk
- Malicious vendor (skill) identified and removed
- Enhanced vendor due diligence process implemented

**ISO 27001:2022** (A.5.22 - Supplier Security Monitoring):
- Supplier (npm registry) security event detected and responded to
- Supplier management procedures updated to prevent recurrence

**GDPR** (Article 28 - Processor Requirements):
- No personal data processed by malicious skill (only Internal/Confidential data)
- Breach notification NOT required ✅

### B. npm Security Report Template

```markdown
# Malicious npm Package Report

**Reporter**: OpenClaw Security Team  
**Contact**: security@openclaw.ai  
**Date**: 2026-02-14  
**Package**: `@attacker/credential-stealer`  
**Versions Affected**: 1.2.3 (possibly others)  

## Summary
This package contains malicious code designed to steal credentials and exfiltrate data to attacker-controlled servers.

## Malicious Behavior
1. **Credential Exfiltration**: Accesses OS keychain without user consent
2. **Data Exfiltration**: Sends stolen credentials to https://attacker.com/collect
3. **Filesystem Persistence**: Creates backdoor in `~/.bashrc`

## Evidence
- Network connections to malicious domain (PCAP attached)
- Decompiled source code showing credential access (attached)
- Hash: sha256:abc123...

## Impact
- 3 production systems compromised
- 14 API keys stolen (all rotated)
- No customer data affected

## Recommendation
**Remove package @attacker/credential-stealer from npm registry immediately.**

## Attachments
- forensics-IRP-003.tar.gz.gpg (encrypted evidence bundle)
```

### C. Related Playbooks

- **[playbook-credential-theft.md](playbook-credential-theft.md)** - If skill exfiltrated credentials
- **[playbook-data-breach.md](playbook-data-breach.md)** - If skill caused data breach
- **[playbook-prompt-injection.md](playbook-prompt-injection.md)** - If skill exploited prompt injection

### D. Useful Commands Reference

```bash
# Find all installed skills across agents
docker ps --filter "label=openclaw-agent" --format "{{.Names}}" | \
  xargs -I {} docker exec {} npm list --depth=0 --json | jq '.dependencies | keys'

# Check skill integrity hashes
./scripts/supply-chain/skill_manifest.py \
  --verify-integrity \
  --skills-dir ~/.openclaw/skills \
  --baseline-hashes skills-integrity-baseline.json

# Test skill in sandboxed environment
docker run --rm --network none \
  -v $(pwd)/skill-under-test:/skill:ro \
  openclaw/skill-sandbox:latest \
  /skill/index.js

# Monitor npm registry for typosquatting
curl -X GET "https://registry.npmjs.org/@openclaw/nonexistent-package" \
  # Should return 404; if 200, possible dependency confusion attack
```

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-14 | Security Team | Initial playbook creation |
| 1.1 | 2026-02-14 | Security Team | Added typosquatting detection section |

**Approval**:
- **CISO**: ✅ Approved 2026-02-14
- **Engineering Lead**: ✅ Technical review 2026-02-14

**Next Review**: 2026-05-14 (quarterly review)
