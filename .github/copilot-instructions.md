# Copilot Instructions — OpenClaw/ClawdBot Security Playbook

***

## 1. Audit History & Current Cycle

- **Cycles 1–3 COMPLETE:** Foundational baseline, drift remediation, local runtime validation, replay validation, and evidence normalization are established.
- **Cycle 4 COMPLETE (Hosted Proof & Detection Evasion Hardening):** Hosted CI trust, detection coverage completion (scenarios 003–005, 007), and detection evasion red-teaming.
- **Current cycle: Cycle 5 — Code Veracity & Implementation**
  - An adversarial code audit (2026-04-24) identified CRITICAL, HIGH, and MEDIUM findings across scripts and automations.
  - All findings are tracked as GitHub Issues with `audit-fix` label and `C5-` identifiers.
  - Findings, batches, and acceptance criteria live in `.github/audit/findings-2026-04-24.md`.

***

## 2. Cycle 5 Operating Rules for the Agent

### Rule 1 — Do not re-open Cycles 1–4 findings
Do not re-examine Cycle 1–4 findings unless a Cycle 5 fix directly touches infrastructure, gateway config, TLS settings, or detection logic — in which case verify no regression against the immutable defaults in Section 6.

### Rule 2 — Fix scope is strict
When implementing a Cycle 5 issue:
- Change **only** the files listed in that issue's "Files affected" section.
- Do not refactor, rename, or improve anything outside scope, even if it looks wrong.
- If a fix requires touching an out-of-scope dependency, STOP and report it as a new finding rather than silently expanding scope.

### Rule 3 — Every fix must make the claim provably true
A fix is complete only when the original claim made by the function or script is demonstrably true via end-to-end logic trace — not just when the code runs without errors. Trace the execution path after every change and confirm the claim holds.

### Rule 4 — Mark every changed line
Add an inline comment at every changed line: `# FIX: C5-[finding-N]`

### Rule 5 — Integration stubs must be explicit
If a fix requires an external integration (`openclaw-detect`, `openclaw-shield`, `openclaw-telemetry`, `clawguard`) that is not yet wired up, implement a proper stub with `NotImplementedError` or equivalent and a `TODO` specifying exactly what the real integration needs. Do not silently no-op.

### Rule 6 — Track all Cycle 5 findings
All new findings and fixes must be recorded in:
- `AUDIT_ROADMAP.md`
- `BATCH_EXECUTION_PLAN.md`
- `DEBT_INVENTORY_ACTIVE.md`
with `C5-` identifiers.

***

## 3. Cycle 5 Batch Execution Map

| Track | Findings | Method | Model |
|---|---|---|---|
| CRITICAL | Broken — will not execute or wrong results | `gem-implementer` interactive, VS Code | GPT-5.4 |
| HIGH | Functional gap — runs but claim is false | Copilot cloud agent (async per issue) | — |
| MEDIUM | Fragile — silent failures, no error handling | Copilot cloud agent (bulk batch) | — |

Acceptance criteria for every issue are the source of truth. PRs without passing criteria must not be merged.

***

## 4. Cycle 4 Deep Dive Areas (Established — Do Not Regress)

### A. Hosted CI Trust (Layer 7)
- Hosted workflows must capture runner-backed evidence.
- Any fix touching `.github/workflows/` must be verified on GitHub-hosted runners, not just local Docker.

### B. Detection Coverage (Layers 2, 5, 6)
- Replay-backed detections exist for scenarios 003 (MCP compromise), 004 (multi-agent coordination), 005 (credential theft via skill), 007 (DoS/resource exhaustion).
- Do not regress existing replay fixtures.

### C. Detection Evasion (Phases 5, 6, 7)
- Detection logic has been red-teamed for case, encoding, whitespace, null-byte, and regex-stress variants.
- Any Cycle 5 fix touching `detections/` must re-run the evasion fixture suite before the PR is merged.

***

## 5. How to Run a Cycle 5 Fix (Workflow)

1. **Open the GitHub Issue** — read acceptance criteria fully before touching code.
2. **Identify all affected files** — listed in the issue. Do not discover new scope mid-fix.
3. **Implement** — one file at a time, marking each changed line with `# FIX: C5-[N]`.
4. **Trace the claim** — after each file change, narrate the execution path proving the original claim is now true.
5. **Run tests** — use the verification step specified in the issue. If no test exists, state exactly what manual verification confirms the fix.
6. **Commit** — one commit per finding: `fix(C5-[N]): [function name] now actually [what it claims]`
7. **Update trackers** — mark finding resolved in `AUDIT_ROADMAP.md` and `DEBT_INVENTORY_ACTIVE.md`.

***

## 6. Immutable Security Defaults (Verify No Drift — All Cycles)

*Any fix touching infrastructure, Docker, TLS, or gateway config must confirm none of these have regressed.*

- Gateway `127.0.0.1:18789`, MCP server `127.0.0.1:8443`
- `user: "1000:1000"` (non-root)
- `cap_drop: [ALL]` with only `NET_BIND_SERVICE` added back
- `read_only: true` with strict `tmpfs`
- `no-new-privileges: true`
- TLS 1.3 only; AES-256-GCM
- Skills: `autoUpdate: false`, `autoInstall: false`, `requireSignature: true`