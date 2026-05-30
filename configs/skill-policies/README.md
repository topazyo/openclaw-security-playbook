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

**Purpose:** Configure the one enforcement lever that the monitoring script actually reads — PGP signature verification.

> **Honesty note (C6-M-11):** Earlier revisions of this file declared a large
> surface of enforcement levers (manifest/integrity validation, source
> validation, pattern-scanning toggles, quarantine triggers, logging config,
> per-skill exceptions). None of those were ever read by any code path —
> editing them produced no behaviour change. They have been **removed** from
> both `enforcement-policy.json` and `enforcement-policy-schema.json` rather
> than left as config-theater. The table below states exactly what is and is
> not enforced.

**Per-field status:**

| Top-level group | Status | Enforced by |
|-----------------|--------|-------------|
| `version`, `last_updated`, `description` | CONSUMED (metadata) | parsed by every jq read; required by schema |
| `validation.signature.required` | **CONSUMED** | `verify_signature()` in `scripts/supply-chain/skill_integrity_monitor.sh` |
| `validation.signature.verify_pgp` | **CONSUMED** | `verify_signature()` in `scripts/supply-chain/skill_integrity_monitor.sh` |
| `validation.signature.trusted_keys` | **CONSUMED** | `verify_signature()` in `scripts/supply-chain/skill_integrity_monitor.sh` (trusted-keys allowlist) |
| `validation.manifest.*` | REMOVED | never read; manifest validation is hardcoded in `validate_manifest` |
| `validation.integrity.*` | REMOVED | never read; integrity check is hardcoded |
| `validation.signature.fail_on_invalid` | REMOVED | never read; an invalid signature always fails `verify_signature` |
| `source_validation.*` | REMOVED | never read |
| `pattern_scanning.*` | REMOVED | never read; scanning is governed by presence of `dangerous-patterns.json` and the `$SKILL_SCAN_INTERVAL` / `$AUTO_QUARANTINE` env vars |
| `quarantine.auto_quarantine` | REMOVED | the policy field was never read; auto-quarantine is driven by the `AUTO_QUARANTINE` env var (read in `scan_all_skills()`) |
| `quarantine.quarantine_on.*` | REMOVED | never read |
| `quarantine.retention_days` | REMOVED | never read; quarantine pruning uses the `QUARANTINE_RETENTION_DAYS` env var (read in `clean_quarantine()`) |
| `quarantine.notify_on_quarantine` | REMOVED | never read; no notification dispatcher exists |
| `logging.*` | REMOVED | never read; logging is hardcoded and rotation uses `LOG_RETENTION_DAYS` / `MAX_LOG_SIZE` env vars |
| `exceptions.skills[]` | REMOVED | never read; no skip-check logic exists |

ADVISORY: there are currently **no** advisory-only fields — a field is either
consumed by code or it has been removed. Quarantine/log retention, scan
interval, and auto-quarantine behaviour are configured via **environment
variables**, not this file (see Environment Variables below).

**Example (this is the entire consumed surface):**

```json
{
  "version": "1.0.0",
  "last_updated": "2026-05-30T12:00:00Z",
  "description": "Skill security enforcement policy",
  "validation": {
    "signature": {
      "required": true,
      "verify_pgp": true,
      "trusted_keys": []
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
        "allowed_permissions": ["filesystem:read", "network:https"],
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

Edit `enforcement-policy.json`. The **only** fields consumed by code are the
signature-verification settings below — there are no other enforcement levers in
this file (see the per-field status table above). To adjust quarantine
retention, auto-quarantine, or scan interval, use the environment variables
listed under Environment Variables instead.

```json
{
  "validation": {
    "signature": {
      "required": true,
      "verify_pgp": true,
      "trusted_keys": []
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

> **Updated for C6-M-11.** The previous version of this contract described
> semantics (enforcement-level routing, source-validation blocking, integrity
> gating, severity→action mapping, dangerous-permission mapping) that were
> **never read from `enforcement-policy.json`** — they were config-theater.
> This contract now lists only what the policy file actually controls; the
> remaining behaviours below are hardcoded in `skill_integrity_monitor.sh` and
> are not policy-configurable.

Policy-file-controlled (read from `enforcement-policy.json`):

- Signature verification is mandatory by default (`validation.signature.required: true`).
- PGP signature verification is enabled by default (`validation.signature.verify_pgp: true`).
- When `validation.signature.trusted_keys` is non-empty, only those keys are accepted (enforced in `verify_signature()`).

Hardcoded in the script (NOT policy-configurable — do not expect these to react to JSON edits):

- An invalid or unverifiable signature always fails `verify_signature` (there is no `fail_on_invalid` toggle).
- Manifest schema validation and SHA-256 integrity checking are always performed by their respective functions.
- Pattern scanning runs whenever `dangerous-patterns.json` is present; there is no enable/disable toggle in this file.
- Auto-quarantine on failure is driven by the `AUTO_QUARANTINE` environment variable, not by `quarantine.auto_quarantine`.

Do not relax the policy-controlled defaults without a documented contract decision and cross-file audit update.

---

## Best Practices

### 1. Keep Signature Verification Mandatory

The only enforcement lever in `enforcement-policy.json` is signature
verification. Keep it locked down:

```json
{
  "validation": {
    "signature": {
      "required": true,
      "verify_pgp": true
    }
  }
}
```

> There is no `enforcement_level` field and no per-skill `exceptions` block —
> those were removed in C6-M-11 because no code read them. Do not re-add them
> expecting a behaviour change.

### 2. Pin Trusted Signing Keys

Populate `validation.signature.trusted_keys` to restrict accepted signers
(empty = any otherwise-valid signature is accepted):

```json
{
  "validation": {
    "signature": {
      "trusted_keys": ["<pgp-key-id-or-fingerprint>"]
    }
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
# Reduce scan frequency (scan interval is an env var, not a policy field)
export SKILL_SCAN_INTERVAL="600"  # 10 minutes
```

> Note: there is no `pattern_scanning` block in `enforcement-policy.json` to
> disable individual checks — those toggles were removed in C6-M-11 because no
> code read them. Tune scan frequency with `SKILL_SCAN_INTERVAL` instead.

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
