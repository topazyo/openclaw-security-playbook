# Cycle 4 Detection Replay Matrix

This matrix maps replay fixtures to the scenario themes, telemetry fields, and expected detections they exercise during Cycle 4. It includes the Cycle 3 baseline plus the scenario coverage expansion added for Cycle 4.

## Replay Coverage

| Replay Case | Scenario Source | Fixture Type | Key Telemetry Fields / Artifacts | Expected Detection Outcome |
|---|---|---|---|---|
| `mcp-path-traversal-positive` | [examples/scenarios/scenario-003-mcp-server-compromise.md](../../examples/scenarios/scenario-003-mcp-server-compromise.md) | Sigma event fixture | `RequestPath`, `QueryString`, `DestinationPort` | `openclaw-mcp-path-traversal.yml` matches |
| `mcp-path-traversal-negative-benign-download` | Legitimate MCP file export download | Sigma event fixture | `RequestPath`, `QueryString` | `openclaw-mcp-path-traversal.yml` does not match |
| `agent-impersonation-webhook-positive` | [examples/scenarios/scenario-004-multi-agent-coordination-attack.md](../../examples/scenarios/scenario-004-multi-agent-coordination-attack.md) | Sigma event fixture | `SkillName`, `Url`, `RequestBody` | `openclaw-agent-impersonation-webhook.yml` matches |
| `agent-impersonation-webhook-negative-slack-notify` | Benign webhook sender usage to external notification endpoint | Sigma event fixture | `SkillName`, `Url`, `RequestBody` | `openclaw-agent-impersonation-webhook.yml` does not match |
| `rag-poisoning-upload-positive` | [examples/scenarios/scenario-005-credential-theft-via-skill.md](../../examples/scenarios/scenario-005-credential-theft-via-skill.md) | Sigma event fixture | `RequestPath`, `Filename`, `DocumentText` | `openclaw-rag-poisoning-upload.yml` matches |
| `rag-poisoning-upload-negative-benign-policy` | Legitimate knowledge-base upload | Sigma event fixture | `RequestPath`, `Filename`, `DocumentText` | `openclaw-rag-poisoning-upload.yml` does not match |
| `expensive-trial-abuse-positive` | [examples/scenarios/scenario-007-denial-of-service-resource-exhaustion.md](../../examples/scenarios/scenario-007-denial-of-service-resource-exhaustion.md) | Sigma event fixture | `EventType`, `RequestPath`, `UserTier`, `Model`, `EstimatedInputTokens`, `MaxTokens` | `openclaw-expensive-trial-abuse.yml` matches |
| `expensive-trial-abuse-negative-enterprise-summary` | Routine low-cost enterprise prompt | Sigma event fixture | `EventType`, `RequestPath`, `UserTier`, `Model`, `EstimatedInputTokens`, `MaxTokens` | `openclaw-expensive-trial-abuse.yml` does not match |
| `gateway-exposure-positive` | Synthetic runtime exposure aligned to `C3-RUN-002` | Sigma event fixture | `Image`, `CommandLine`, `DestinationPort`, `DestinationIp` | `openclaw-gateway-exposure.yml` matches |
| `gateway-exposure-negative-localhost` | Immutable default localhost bind | Sigma event fixture | `DestinationPort`, `DestinationIp` | `openclaw-gateway-exposure.yml` does not match |
| `tls-downgrade-positive` | Synthetic TLS regression aligned to Batch C3-A insecure path | Sigma event fixture | `DestinationPort`, `TlsVersion` | `openclaw-tls-downgrade.yml` matches |
| `runtime-hardening-drift-positive` | Synthetic insecure container launch aligned to Batch C3-A | Sigma event fixture | `Image`, `CommandLine` | `openclaw-runtime-hardening-drift.yml` matches |
| `skill-child-process-positive` | [examples/scenarios/scenario-002-malicious-skill-deployment.md](../../examples/scenarios/scenario-002-malicious-skill-deployment.md) | Sigma event fixture | `ParentImage`, `Image`, `CommandLine` | `openclaw-skill-child-process.yml` matches |
| `skill-child-process-negative-pip-install` | Known false-positive trap from legitimate install/bootstrap activity | Sigma event fixture | `ParentImage`, `Image`, `CommandLine` | `openclaw-skill-child-process.yml` suppressed by `filter_known_safe` |
| `credential-harvest-positive` | [examples/scenarios/scenario-006-credential-theft-conversation-history.md](../../examples/scenarios/scenario-006-credential-theft-conversation-history.md) and prompt-driven file access | Sigma event fixture | `Image`, `CommandLine`, `TargetFilename` | `openclaw-credential-harvest.yml` matches |
| `soul-md-positive` | [examples/scenarios/scenario-002-malicious-skill-deployment.md](../../examples/scenarios/scenario-002-malicious-skill-deployment.md) persistence stage | Sigma event fixture | `Image`, `CommandLine`, `TargetFilename`, `EventType` | `openclaw-soul-md-modification.yml` matches |
| `supply-chain-drift-positive` | [examples/scenarios/scenario-002-malicious-skill-deployment.md](../../examples/scenarios/scenario-002-malicious-skill-deployment.md) | Sigma event fixture | `TargetFilename`, `EventType` | `openclaw-supply-chain-drift.yml` matches |
| `gateway-config-drift-positive` | Synthetic pre-exposure config tampering | Sigma event fixture | `TargetFilename`, `EventType` | `openclaw-gateway-config-drift.yml` matches |
| `yara-malicious-skill-positive` | [scenario-002-malicious-skill-deployment.md](scenario-002-malicious-skill-deployment.md) | YARA file fixture | Skill file contents | `OpenClaw_Skill_Dangerous_Patterns` matches |
| `yara-soul-injection-positive` | Memory poisoning / persistence from [ATLAS-mapping.md](ATLAS-mapping.md) | YARA file fixture | `SOUL.md` contents | `OpenClaw_SOUL_Injection_Persistence` matches |
| `yara-gateway-config-positive` | Synthetic gateway bind drift | YARA config fixture | Gateway config contents | `OpenClaw_Gateway_Exposed_Config` matches |

## Adversarial Variants

| Replay Case | Evasion Theme | Expected Outcome |
|---|---|---|
| `mcp-path-traversal-evasion-encoded-null` | URL encoding plus null-byte suffix | `openclaw-mcp-path-traversal.yml` still matches |
| `rag-poisoning-upload-evasion-case-whitespace-null` | Case manipulation, whitespace chunking, null-byte insertion | `openclaw-rag-poisoning-upload.yml` still matches |
| `expensive-trial-abuse-evasion-case` | Case manipulation in tier/model fields | `openclaw-expensive-trial-abuse.yml` still matches |
| `gateway-exposure-evasion-case-whitespace` | Case manipulation and whitespace chunking in wrapped Node invocation | `openclaw-gateway-exposure.yml` still matches |

## Execution

Local Sigma-only replay:

```bash
python scripts/verification/validate_detection_replay.py --skip-yara
```

Full replay with YARA available:

```bash
python scripts/verification/validate_detection_replay.py --require-yara
```

This replay matrix is the source-backed mapping for `C3-DET-002` and `C4-DET-002`. Update it whenever a new fixture or detection rule is added.