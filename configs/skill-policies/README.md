# Skill Security Policies

> **Policy configuration for MCP skill validation and enforcement**

This directory contains security policies for validating and monitoring Model Context Protocol (MCP) skills in ClawdBot deployments.

---

## Policy Files

### 1. allowlist.json
**Purpose:** Define approved skills, sources, and authors

**Configuration:**
- **Trusted sources** - GitHub organizations automatically trusted
- **Approved skills** - Specific skills with version constraints
- **Deprecated skills** - Track outdated versions
- **Blocked items** - Known malicious skills/authors
- **Domain lists** - Allowed/blocked domains

**Example:**
```json
{
  "sources": {
    "trusted": [
      "https://github.com/anthropics/",
      "https://github.com/modelcontextprotocol/"
    ]
  },
  "skills": {
    "approved": [
      {
        "id": "filesystem-mcp",
        "version": ">=0.5.0",
        "allowed_permissions": ["filesystem:read"]
      }
    ]
  }
}
```

---

### 2. dangerous-patterns.json
**Purpose:** Define regex patterns for detecting dangerous code

**Patterns Include:**
- Code execution (exec, eval)
- Shell injection
- SQL injection
- Path traversal
- Hardcoded credentials
- Unsafe deserialization
- Weak cryptography
- Command injection

**Severity Levels:**
- `critical` - Block immediately
- `high` - Block or warn
- `medium` - Warn
- `low` - Log only

**Example:**
```json
{
  "patterns": [
    {
      "id": "exec-dangerous",
      "pattern": "\\b(exec|eval)\\s*\\(",
      "severity": "critical",
      "description": "Direct code execution"
    }
  ]
}
```

---

### 3. manifest-schema.json
**Purpose:** JSON Schema for skill manifest validation

**Validated Fields:**
- Required: name, version, type, author
- Optional: license, repository, dependencies
- Security: integrity hashes, signatures
- Permissions: declared capabilities
- Compatibility: platform/version constraints

**Usage:**
```bash
# Validate manifest with ajv-cli
ajv validate -s manifest-schema.json -d skill-manifest.json
```

### Policy schema validation (ajv-cli)

```bash
# Validate policy files with ajv-cli
ajv validate -s allowlist-schema.json -d allowlist.json
ajv validate -s dangerous-patterns-schema.json -d dangerous-patterns.json
ajv validate -s enforcement-policy-schema.json -d enforcement-policy.json
```

---

### 4. enforcement-policy.json
**Purpose:** Configure enforcement actions and monitoring

**Settings:**
- **Enforcement levels** - block, warn, log
- **Validation rules** - manifest, integrity, signatures
- **Pattern scanning** - severity-based actions
- **Quarantine rules** - automatic isolation
- **Monitoring** - continuous scanning
- **Notifications** - alerts and webhooks

**Example:**
```json
{
  "enforcement_level": {
    "production": "block",
    "development": "warn"
  },
  "pattern_scanning": {
    "severity_actions": {
      "critical": "block",
      "high": "block",
      "medium": "warn"
    }
  }
}
```

---

## Usage

### With Monitoring Script

```bash
# Start monitoring with policies
./scripts/supply-chain/skill_integrity_monitor.sh --start

# Run one-time scan
./scripts/supply-chain/skill_integrity_monitor.sh --scan

# Validate specific skill
./scripts/supply-chain/skill_integrity_monitor.sh \
  --validate /path/to/skill-manifest.json
```

### Environment Variables

```bash
export OPENCLAW_CONFIG="$HOME/.openclaw/config"
export OPENCLAW_SKILLS="$HOME/.openclaw/skills"
export AUTO_QUARANTINE="true"
export SKILL_SCAN_INTERVAL="300"  # 5 minutes
```

---

## Customization

### Adding Approved Skills

Edit `allowlist.json`:

```json
{
  "skills": {
    "approved": [
      {
        "id": "my-custom-skill",
        "name": "custom-mcp-tool",
        "version": ">=1.0.0",
        "source": "https://github.com/myorg/mcp-tool",
        "allowed_permissions": [
          "filesystem:read",
          "network:https"
        ],
        "notes": "Internal tool for team"
      }
    ]
  }
}
```

### Adding Custom Patterns

Edit `dangerous-patterns.json`:

```json
{
  "patterns": [
    {
      "id": "custom-pattern",
      "name": "My dangerous pattern",
      "pattern": "dangerous_function\\(",
      "severity": "high",
      "description": "Custom risky pattern",
      "recommendation": "Use safe alternative"
    }
  ]
}
```

### Adjusting Enforcement

Edit `enforcement-policy.json`:

```json
{
  "enforcement_level": {
    "production": "block",    // Block in production
    "development": "warn"     // Warn in dev
  },
  "quarantine": {
    "auto_quarantine": true,  // Enable auto-quarantine
    "quarantine_on": {
      "integrity_failure": true,
      "dangerous_patterns": {
        "critical": true,
        "high": true          // Also quarantine HIGH severity
      }
    }
  }
}
```

---

## Policy Enforcement Workflow

```
┌─────────────────────┐
│  Skill Installed    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Validate Manifest  │───────► Fail → Quarantine
└──────────┬──────────┘
           │ Pass
           ▼
┌─────────────────────┐
│  Check Allowlist    │───────► Not Approved → Block
└──────────┬──────────┘
           │ Approved
           ▼
┌─────────────────────┐
│  Verify Integrity   │───────► Mismatch → Quarantine
└──────────┬──────────┘
           │ Pass
           ▼
┌─────────────────────┐
│  Scan Patterns      │───────► Critical/High → Block + Quarantine
└──────────┬──────────┘         Medium → Warn
           │ Pass               Low → Log
           ▼
┌─────────────────────┐
│  Check Permissions  │───────► Dangerous → Block/Warn (policy-mapped)
└──────────┬──────────┘
           │ OK
           ▼
┌─────────────────────┐
│  Allow Execution    │
└─────────────────────┘
```

### Enforcement Semantics Contract (POLICY-SEM-001)

The following semantics are treated as contract-level defaults for production:

- `production` enforcement level is `block`.
- Untrusted sources are blocked (`source_validation.block_untrusted: true`).
- Signature and integrity validation are mandatory (`validation.signature.required: true`, `validation.integrity.required: true`).
- Unsigned skills are rejected (`validation.integrity.allow_unsigned: false`).
- Invalid signatures fail validation (`validation.signature.fail_on_invalid: true`).
- Pattern scanning actions are stable:
  - `critical` → `block` + quarantine
  - `high` → `block` + quarantine
  - `medium` → `warn`
  - `low` → `log`
- Dangerous permissions are policy-mapped and deterministic:
  - `process:exec` → `block`
  - `network:unrestricted` → `block`
  - `filesystem:write` → `warn`
  - `secrets:write` → `block`

Do not relax these defaults without a documented contract decision and cross-file audit update.

---

## Best Practices

### 1. Keep Production Enforcement Immutable

```json
"enforcement_level": {
  "production": "block"
}
```

### 2. Use Exceptions Sparingly

```json
{
  "exceptions": {
    "skills": [
      {
        "id": "legacy-skill",
        "reason": "Legacy system integration",
        "expiry": "2026-12-31",           // Set expiration
        "skip_checks": ["pattern_scanning"],
        "approved_by": "security-team"    // Track approval
      }
    ]
  }
}
```

### 3. Monitor and Iterate

- Review quarantine logs weekly
- Adjust patterns based on false positives
- Update allowlist as new skills are vetted
- Track enforcement metrics

### 4. Version Control Policies

```bash
# Track policy changes
git add configs/skill-policies/
git commit -m "Update skill policies: Add new approved skill"

# Review policy changes in PR
git diff configs/skill-policies/allowlist.json
```

---

## Testing Policies

### Test Allowlist

```bash
# Add test skill to allowlist
cat > /tmp/test-skill-manifest.json << 'EOF'
{
  "name": "test-skill",
  "version": "1.0.0",
  "type": "mcp-server",
  "author": {"name": "Test"}
}
EOF

# Validate
./scripts/supply-chain/skill_integrity_monitor.sh \
  --validate /tmp/test-skill-manifest.json
```

### Test Dangerous Patterns

```bash
# Create skill with dangerous code
echo "eval(user_input)" > /tmp/dangerous.py

# Scan should detect it
grep -E "\b(exec|eval)\s*\(" /tmp/dangerous.py
```

### Test Enforcement Levels

```bash
# Test in development mode
ENVIRONMENT=development ./skill_integrity_monitor.sh --scan

# Test in production mode
ENVIRONMENT=production ./skill_integrity_monitor.sh --scan
```

---

## Compliance

### OWASP SAMM Alignment

- **Governance** - Policy-based enforcement
- **Verification** - Integrity checking
- **Security Testing** - Pattern scanning

### NIST SSDF Alignment

- **PO.3** - Software component transparency (SBOM)
- **PS.1** - Protect code from tampering (integrity)
- **PS.2** - Review code for vulnerabilities (patterns)
- **RV.1** - Identify vulnerabilities (scanning)

---

## Troubleshooting

### Policy Not Loading

```bash
# Check file permissions
ls -l configs/skill-policies/

# Validate JSON syntax
jq empty configs/skill-policies/allowlist.json

# Check environment variables
echo $OPENCLAW_CONFIG
```

### False Positives

```bash
# Add exception to pattern
{
  "pattern": "eval\(",
  "exceptions": ["safe_eval"]  // Function name to ignore
}

# Or use inline suppression in code
# nosec - documented exception
eval(trusted_input)
```

### High Resource Usage

```bash
# Reduce scan frequency
export SKILL_SCAN_INTERVAL="600"  # 10 minutes

# Disable expensive checks in dev
{
  "pattern_scanning": {
    "scan_dependencies": false
  }
}
```

---

## Security Considerations

⚠️ **Important Notes:**

1. **Policies are not foolproof** - Determined attackers can bypass pattern matching
2. **Regular updates required** - New attack vectors emerge constantly
3. **Defense in depth** - Use policies alongside other security controls
4. **Monitor exceptions** - Exceptions should be temporary and reviewed
5. **Version control** - Track all policy changes for audit trail

---

## References

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [Model Context Protocol Specification](https://github.com/modelcontextprotocol/specification)
- [ClawdBot Supply Chain Security Guide](../../docs/guides/05-supply-chain-security.md)

---

**Version:** 1.0.0  
**Last Updated:** February 14, 2026  
**Maintained by:** ClawdBot Security Team
