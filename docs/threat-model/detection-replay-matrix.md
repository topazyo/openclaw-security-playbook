# Cycle 3 Detection Replay Matrix

This matrix maps replay fixtures to the scenario themes, telemetry fields, and expected detections they exercise during Cycle 3.

## Replay Coverage

| Replay Case | Scenario Source | Fixture Type | Key Telemetry Fields / Artifacts | Expected Detection Outcome |
|---|---|---|---|---|
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

## Execution

Local Sigma-only replay:

```bash
python scripts/verification/validate_detection_replay.py --skip-yara
```

Full replay with YARA available:

```bash
python scripts/verification/validate_detection_replay.py --require-yara
```

This replay matrix is the source-backed mapping for `C3-DET-002`. Update it whenever a new fixture or detection rule is added.