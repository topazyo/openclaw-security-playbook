# DEBT_INVENTORY_ACTIVE

> **Audit Cycle:** Cycle 4
> **Created:** 2026-03-14
> **Status:** Active

---

## Live Debt Ledger

| ID | Theme | Severity | Status | Planned Batch | Evidence Gap | Next Move |
|----|-------|----------|--------|---------------|--------------|-----------|
| **C4-CI-001** | Hosted CI proof | HIGH | COMPLETE | C4-A | Live `main` reruns retained hosted runtime and replay artifacts under the Cycle 4 archive | Preserve the hosted evidence paths for Cycle 4 closeout |
| **C4-CI-002** | Runner portability | MEDIUM | COMPLETE | C4-A / C4-E | Hosted runner-delta artifacts now record Docker, seccomp, YARA, and path assumptions for both jobs | Treat additional OS parity as optional follow-on work |
| **C4-DET-001** | Detection coverage | HIGH | COMPLETE | C4-B | Local replay-backed coverage has been added for scenarios 003, 004, 005, and 007 | Preserve the new rules and include them in the next hosted replay run |
| **C4-DET-002** | Replay matrix completeness | MEDIUM | COMPLETE | C4-B | The working-tree replay matrix now covers all seven documented attack scenarios | Keep the matrix aligned as C4-C and C4-D add more fixtures |
| **C4-EVA-001** | Detection evasion | HIGH | COMPLETE | C4-C | Adversarial replay fixtures now exercise encoding, case, whitespace, and null-byte variants in the local replay pack | Preserve the fixtures and include them in the next hosted replay run |
| **C4-EVA-002** | Regex resilience | MEDIUM | COMPLETE | C4-C | Sigma regex-style modifiers are now blocked in replay validation and current YARA rules pass a high-risk regex heuristic scan | Keep the guardrail tests green as new detections are added |
| **C4-CHAIN-001** | Cross-layer orchestration | HIGH | COMPLETE | C4-D | A scripted malicious-skill chain now produces correlated detection, forensics, containment, and reporting artifacts under one incident ID | Preserve the exercise and include it in Cycle 4 closeout evidence |

Cycle 3 is archived as complete in `archive/audit-artifacts-2026-03-14/CYCLE3_CLOSEOUT_EVIDENCE_2026-03-14.md`, which remains the local baseline for Cycle 4 hosted-proof work.

2026-03-14 execution note: hosted run `23096000651` (`Runtime Security Regression`) succeeded and retained artifact `cycle3-runtime-evidence`; hosted run `23096001103` (`Detection Replay Validation`) also succeeded but published `0` artifacts. Full evidence note: `archive/audit-artifacts-2026-03-14/CYCLE4_BATCH_C4A_HOSTED_EVIDENCE_2026-03-14.md`.
2026-03-14 execution note: hosted rerun `23096254983` (`Runtime Security Regression`) retained artifact `cycle3-runtime-evidence`; hosted rerun `23096255321` (`Detection Replay Validation`) retained artifact `detection-replay-evidence` with replay summary and runner-delta output. Evidence note: `archive/audit-artifacts-2026-03-14/CYCLE4_BATCH_C4A_HOSTED_EVIDENCE_2026-03-14.md`.
2026-03-14 execution note: local Batch C4-B replay validation passed with explicit coverage for scenarios 003, 004, 005, and 007. Evidence note: `archive/audit-artifacts-2026-03-14/CYCLE4_BATCH_C4B_DETECTION_COVERAGE_2026-03-14.md`.
2026-03-14 execution note: local Batch C4-C replay validation passed with adversarial evasion fixtures and matcher guardrails. Evidence note: `archive/audit-artifacts-2026-03-14/CYCLE4_BATCH_C4C_EVASION_HARDENING_2026-03-14.md`.
2026-03-14 execution note: local Batch C4-D malicious-skill chain exercise passed and archived a correlated incident bundle for `INC-2026-C4D-001`. Evidence note: `archive/audit-artifacts-2026-03-14/CYCLE4_BATCH_C4D_ATTACK_CHAIN_2026-03-14.md`.
2026-03-14 closeout note: `archive/audit-artifacts-2026-03-14/CYCLE4_CLOSEOUT_EVIDENCE_2026-03-14.md` consolidates the full Cycle 4 evidence set as the final source of truth.

---

## Cycle 5 Live Debt Ledger

| ID | Theme | Severity | Status | Planned Batch | Evidence Gap | Next Move |
|----|-------|----------|--------|---------------|--------------|-----------|
| **C5-finding-1** | Policy validator honesty | CRITICAL | COMPLETE | Batch C / Issue #6 | `tools/policy-validator.py` now evaluates real `SEC-003` and `SEC-005` rules from repo-backed policy/checklist artifacts and fails closed on noncompliance instead of returning unconditional passes. | Preserve the acceptance and claim-based regression suites as the guardrail for future policy-validator edits. |
| **C5-finding-2** | CLI orchestration honesty | CRITICAL | COMPLETE | Batch B / Issue #5 | `playbook execute` now performs real phase dispatch, artifact validation, notification routing, and post-phase evidence collection instead of printing no-op theater. | Preserve the new claim-based regression suites as the acceptance guard for future CLI orchestration edits. |
| **C5-finding-3** | Backup verification truthfulness | CRITICAL | COMPLETE | Batch D | `verify_3_2_1_compliance()` now reports 3-2-1 status from real local, snapshot, and offsite evidence instead of accepting alias mismatches, manifest-only artifacts, or snapshot tag-key false positives. | Preserve the new `Test321Strategy` claim regressions as the guardrail for future backup-verification edits. | <!-- FIX: C5-finding-3 -->
| **C5-finding-4** | GDPR compliance reporter honesty | CRITICAL | OPEN | Batch E / Issue #13 | GDPR compliance reporting is tracked in GitHub issue `#13` because the reporter still calls an undefined framework path. | Implement Batch E strictly within `tools/compliance-reporter.py` and `tools/openclaw-cli.py`. |
| **C5-finding-5** | ISO27001 compliance reporter honesty | CRITICAL | OPEN | Batch E / Issue #13 | ISO27001 reporting is tracked in GitHub issue `#13` because the report contract still omits counts and can hardcode a false-green percentage. | Implement Batch E strictly within `tools/compliance-reporter.py` and `tools/openclaw-cli.py`. |
| **C5-finding-6** | Certificate expiry scan truthfulness | CRITICAL | COMPLETE | Batch F / Issue #14 | `check_expiry()` validates `openssl` exit code and stdout, catches all `OSError` launch failures, attaches `tzinfo=timezone.utc` explicitly (no more naive/aware `TypeError`), and returns a deterministic `status` field on every path. `certificates()` renders healthy/expiring/unreadable and guards `None` days. `pytest tests/unit/test_report_weekly_cli.py -q` — 10 passed. | No follow-up action required. |
| **C5-finding-8** | Incident simulation routing honesty | HIGH | COMPLETE | Batch B / Issue #5 | `simulate incident` now routes each supported scenario to a distinct playbook and artifact set with hardened incident payloads. | Keep simulator payloads aligned with orchestration validation rules as new scenarios are added. |
| **C5-finding-7** | Vulnerability scan false-green prevention | HIGH | COMPLETE | Batch H / Issue #16 | `run_scan()` summary now carries `coverage_complete` (bool) and `required_tools_skipped` (list); `vulnerability()` CLI exits non-zero with an explicit "[✗] Scan incomplete" message when required tools are absent — no false-green printed. Module docstring legacy syntax corrected (L-01). Commit ff590ee. | No follow-up action required. |
| **C5-finding-9** | IOC scanner capability honesty | HIGH | OPEN | Batch I / Issue #17 | IOC scanner capability claims are tracked in GitHub issue `#17` because unsupported integrations still overstate scanner coverage. | Implement Batch I strictly within `scripts/incident-response/ioc-scanner.py`. |
| **C5-finding-10** | Forensics collector capability honesty | HIGH | COMPLETE | Batch K / Issue #19 | Module docstring and `collect_disk_metadata()` now accurately describe partition metadata collection (not disk imaging) and SHA-256 checksums (not cryptographic signing). Evidence item description updated. | Verified: `pytest tests/integration/test_modified_function_claims.py tests/integration/test_playbook_procedures.py -q -k "forensics"` (3 passed). |
| **C5-finding-11** | Auto-containment implementation honesty | HIGH | OPEN | Batch G / Issue #15 | Auto-containment implementation scope is tracked in GitHub issue `#15` because the script still implies unsupported containment actions. | Implement Batch G strictly within `scripts/incident-response/auto-containment.py` and `docs/policies/incident-response-policy.md`. |
| **C5-finding-12** | Notification delivery honesty | HIGH | COMPLETE | Batch J / Issue #18 | Fixed in commit 409c186. `send_email_notification` raises `NotImplementedError` instead of silently returning `True`; `notify_all` catches it explicitly and returns `False` when all channels fail. | Verified: `pytest tests/integration/test_modified_function_claims.py tests/integration/test_playbook_procedures.py -q -k notification` passes (2/2). |
| **C5-finding-13** | Shell evidence containment honesty | HIGH | COMPLETE | Batch L / Issue #20 | `--containment` no longer claims network blocking. Script header, `print_help()`, and the containment block describe service/container stops only; two pipefail traps (`ps|grep`, `systemctl|grep`) that aborted the script before containment ran are fixed. | Verified: `pytest tests/unit/test_collect_evidence_script.py tests/unit/test_collect_evidence_function_claims.py -q` (4 passed). |
| **C5-finding-14** | Forensics runbook CLI parity | HIGH | COMPLETE | Batch K / Issue #19 | Runbook Step 1.5 now uses `--incident` and `--level full` (supported). Removed unsupported `--incident-id`, `--output`, `--collect all`. Artifact list updated to reflect actual collection. | Issue #19. |
| **C5-finding-15** | Auto-containment policy parity | HIGH | OPEN | Batch G / Issue #15 | Auto-containment policy parity is tracked in GitHub issue `#15` because the policy example still advertises unsupported flags. | Implement Batch G strictly within `scripts/incident-response/auto-containment.py` and `docs/policies/incident-response-policy.md`. |
| **C5-finding-16** | Detection replay YARA coverage honesty | MEDIUM | COMPLETE | Batch M / Issue #21 | `evaluate_yara_case()` returns `passed=False` with "coverage-incomplete" details when YARA is unavailable without `--require-yara`. `run_validation()` appends a `_yara_coverage` sentinel. `main()` returns exit 2 and prints `[COVERAGE-INCOMPLETE]`. Commit ed1162a. | `pytest tests/security/test_detection_replay_validation.py -q` — 7 passed. |
| **C5-finding-17** | Telemetry verification honesty | MEDIUM | COMPLETE | Batch N / Issue #22 | Check 6 in `verify_openclaw_security.sh` now applies three-state telemetry logic: active (log mtime ≤3600 s), configured-but-stale (log present but old), or unverifiable (no config/log). Config file alone no longer reports active monitoring. | commit 0a62cde — `pytest tests/integration/test_cycle5_claim_regressions.py -q` (28 passed). |
| **C5-finding-18** | Database migration honesty | MEDIUM | COMPLETE | Batch O / Issue #23 | `_run_migrate()` raises `NotImplementedError` with full contract docstring; `main(['migrate'])` catches it, prints to stderr, returns exit code 2. Silent no-op replaced; callers fail closed. | Verified: `pytest tests/unit/test_clawdbot_runtime.py -q` (3 passed). |
| **C5-finding-19** | Forensics collector missing-tool degradation honesty | MEDIUM | COMPLETE | Batch K / Issue #19 | `collect_network_capture()` now adds an explicit `{"status": "degraded"}` manifest entry when tcpdump is missing or fails. `collect_all()` records it in `failed_steps` and raises `RuntimeError`. | Issue #19. |
| **C5-finding-20** | Community tools guide parity | MEDIUM | COMPLETE | Batch N / Issue #22 | `verify_openclaw_security.sh` header comment corrected: `07-community-tools-integration.md` → `08-community-tools-integration.md`. | commit 0a62cde. |
| **C5-finding-21** | Vulnerability CLI help parity | LOW | OPEN | Batch H / Issue #16 | Vulnerability CLI help parity is tracked in GitHub issue `#16` because legacy command examples still remain in the scan surface. | Implement Batch H strictly within `src/clawdbot/scan_vulnerability.py` and `tools/openclaw-cli.py`. |
| **C5-finding-22** | Security training notification parity | LOW | COMPLETE | Batch J / Issue #18 | Fixed in commit 409c186. Training now documents only implemented notification channels (Slack, PagerDuty, Jira) and explicitly states that email routing and GDPR breach tracking are not implemented. | Verified: notification routing section updated; GDPR claim corrected. |
| **C5-finding-23** | Evidence guide output parity | LOW | COMPLETE | Batch L / Issue #20 | Evidence Collection section in `docs/guides/06-incident-response.md` now matches the real helper: full banner, five numbered next-step lines, containment notice that network is not blocked, and exit codes 0 / 1 / 2 each shown. | Verified: `pytest tests/unit/test_collect_evidence_script.py tests/unit/test_collect_evidence_function_claims.py -q` (4 passed). |
| **C5-finding-24** | Phantom integration guard allowlist dead code | CRITICAL | COMPLETE | Batch P / `topazyo/issue9` | Guard built `allowed_paths` but never consulted it in the scan loop, so every allowlisted file was still reported as a violation. Fixed by adding `if rel_path in allowed_paths: continue` and adding `.github/workflows/lint.yml` to the allowlist. | Verify on GitHub-hosted runner CI run for `topazyo/issue9`. |

2026-04-25 execution note: Batch C issue `#6` is ready for closure. Local evidence commands `python tools/policy-validator.py --policy SEC-003`, `python tools/policy-validator.py --policy SEC-005`, and `pytest tests/security/test_policy_compliance.py tests/security/test_policy_validator_claims.py -q` passed with `18 passed`.

2026-04-25 execution note: Batch B issue `#5` is ready for closure. Local evidence command `pytest tests/unit/test_playbook_cli.py tests/unit/test_openclaw_cli_claims.py tests/unit/test_ioc_scanner.py tests/unit/test_ioc_scanner_claims.py tests/unit/test_incident_simulator_claims.py tests/unit/test_collect_evidence_script.py tests/unit/test_collect_evidence_function_claims.py -q` passed with `44 passed`.

2026-04-26 planning note: the remaining open Cycle 5 findings are now mapped to GitHub issues `#13` through `#23` so tracker state, file scope, and acceptance criteria stay synchronized during remediation.

---

## Archived Prior Cycle

| ID | Theme | Status | Evidence Reference |
|----|-------|--------|--------------------|
| **C3-RUN-001** | Runtime validation | ARCHIVED-COMPLETE | `archive/audit-artifacts-2026-03-14/cycle-3-runtime/secure` |
| **C3-RUN-002** | Runtime validation | ARCHIVED-COMPLETE | `archive/audit-artifacts-2026-03-14/cycle-3-runtime/insecure` |
| **C3-DET-001** | Detection replay | ARCHIVED-COMPLETE | `scripts/verification/validate_detection_replay.py` |
| **C3-DET-002** | Detection replay | ARCHIVED-COMPLETE | `docs/threat-model/detection-replay-matrix.md` |
| **C3-AUTO-001** | CI regression | ARCHIVED-COMPLETE | `.github/workflows/runtime-security-regression.yml`, `.github/workflows/detection-replay-validation.yml` |
| **C3-EVID-001** | Evidence normalization | ARCHIVED-COMPLETE | `tools/openclaw-cli.py report evidence-snapshot` |

---

## Priority View

### Immediate

- None. All mandatory Cycle 4 debt items are complete.

### Next

- Optional: expand hosted parity beyond Ubuntu if future audit scope requires it.

### Follow-On

- Preserve Cycle 4 evidence paths during any subsequent detection changes.

---

## Update Rule

When a Cycle 4 item moves, update:

1. `AUDIT_ROADMAP.md` for finding-level state.
2. `BATCH_EXECUTION_PLAN.md` for sequencing and merge-gate impact.
3. `DEBT_INVENTORY_ACTIVE.md` for live execution status.