# ClawdBot / OpenClaw — Security Audit CLAUDE.md
> Cycle 5 — Code Veracity & Implementation

***

## Project Context

Security detection platform for agentic AI threats (MCP compromise, multi-agent coordination, credential theft, DoS). Audit findings from 2026-04-24 are tracked as GitHub Issues with `audit-fix` label and `C5-` identifiers. All findings, batches, and acceptance criteria live in `.github/audit/findings-2026-04-24.md`.

**Cycle status:**
- Cycles 1–4: COMPLETE. Do not re-open unless a C5 fix directly touches infrastructure, gateway config, TLS, or detection logic — then verify no regression against Section: Immutable Security Defaults.
- Cycle 5 ACTIVE: adversarial code audit findings — CRITICAL / HIGH / MEDIUM.

***

## Bash Commands

```bash
# Run a single test by name (never the full suite unless explicitly asked)
pytest tests/test_<module>.py::test_<name> -v

# Run evasion fixture suite (required before merging any detections/ fix)
pytest tests/evasion/ -v

# Verify Docker security posture
docker inspect <container> | jq '.[].HostConfig | {CapDrop, ReadonlyRootfs, SecurityOpt, UsernsMode}'

# Check TLS version in use
openssl s_client -connect 127.0.0.1:8443 -tls1_3

# Commit format for C5 fixes (one commit per finding)
git commit -m "fix(C5-N): <function name> now actually <what it claims>"
```

***

## Operating Rules — Read Before Every Fix

### Rule 1 — Scope is strict
Change **only** files listed in the issue's "Files affected" section. Do not refactor, rename, or improve anything outside that list, even if it looks wrong. If a fix requires touching an out-of-scope file, **STOP** — report it as a new finding rather than silently expanding scope.

### Rule 2 — Every fix must make the claim provably true
A fix is complete only when the original claim made by the function or script is demonstrably true via end-to-end logic trace — not just when the code runs without errors. After every file change, narrate the execution path that proves the claim holds.

### Rule 3 — Mark every changed line
Add an inline comment at every changed line:
```python
# FIX: C5-N
```

### Rule 4 — Integration stubs must be explicit
If a fix requires an external integration (`openclaw-detect`, `openclaw-shield`, `openclaw-telemetry`, `clawguard`) that is not yet wired up, implement a proper stub with `NotImplementedError` or equivalent and a `TODO` specifying exactly what the real integration requires. Never silently no-op.

### Rule 5 — Do not regress Cycle 4 baselines
Any fix touching `.github/workflows/`, `detections/`, Docker, TLS, or gateway config must:
- Verify against Immutable Security Defaults (bottom of this file)
- Re-run the evasion fixture suite for `detections/` changes
- Confirm hosted CI evidence (not local Docker) for workflow changes

### Rule 6 — Track all findings
New findings and fixes must be recorded in:
- `AUDIT_ROADMAP.md`
- `BATCH_EXECUTION_PLAN.md`
- `DEBT_INVENTORY_ACTIVE.md`

with `C5-` identifiers.

***

## Cycle 5 Execution Workflow

**For every issue, in this exact order:**

1. Open the GitHub Issue — read acceptance criteria fully before touching any code
2. Identify affected files — listed in the issue; do not discover new scope mid-fix
3. Implement — one file at a time, marking each changed line with `# FIX: C5-N`
4. Trace the claim — narrate execution path proving original claim is now true
5. Run verification — use the step specified in the issue; if none, state exactly what manual check confirms the fix
6. Commit — one commit per finding using the format above
7. Update trackers — mark resolved in `AUDIT_ROADMAP.md` and `DEBT_INVENTORY_ACTIVE.md`

***

## Cycle 5 Finding Severity Guide

| Severity | Definition | Mode |
|----------|------------|------|
| CRITICAL | Broken — will not execute or produces wrong results | Interactive, one finding at a time, full trace required |
| HIGH | Functional gap — runs but the claim is false | Interactive, per-issue, acceptance criteria are the merge gate |
| MEDIUM | Fragile — silent failures, missing error handling | Can batch, but each fix still requires its own commit and trace |

PRs without passing acceptance criteria must not be merged.

***

## Cycle 4 Baselines (Do Not Regress)

**Hosted CI Trust**
Hosted workflows must capture runner-backed evidence. Any fix to `.github/workflows/` must be verified on GitHub-hosted runners, not local Docker.

**Detection Coverage**
Replay-backed detections exist for: 003 (MCP compromise), 004 (multi-agent coordination), 005 (credential theft via skill), 007 (DoS/resource exhaustion). Do not regress existing replay fixtures.

**Detection Evasion**
Detection logic has been red-teamed for case, encoding, whitespace, null-byte, and regex-stress variants. Any C5 fix touching `detections/` must re-run the full evasion fixture suite before merge.

***

## Immutable Security Defaults

*Verify no drift on any fix touching infrastructure, Docker, TLS, or gateway config.*

| Setting | Required Value |
|---------|---------------|
| Gateway | `127.0.0.1:18789` |
| MCP server | `127.0.0.1:8443` |
| Container user | `1000:1000` (non-root) |
| cap_drop | `[ALL]` — only `NET_BIND_SERVICE` added back |
| Filesystem | `read_only: true` with strict `tmpfs` |
| Privilege escalation | `no-new-privileges: true` |
| TLS | 1.3 only; AES-256-GCM |
| Skills | `autoUpdate: false`, `autoInstall: false`, `requireSignature: true` |

If any of these values have drifted in the branch being fixed, report it immediately as a new finding before proceeding with the original fix.

***

## Anti-Patterns — Never Do These

- Do not run the full test suite when a single-test verification suffices
- Do not merge a PR if acceptance criteria are not explicitly checked
- Do not silently swallow exceptions — all error paths must log or raise
- Do not expand fix scope mid-implementation without filing a new finding first
- Do not commit multiple findings in a single commit
- Do not re-open Cycles 1–4 without explicit instruction