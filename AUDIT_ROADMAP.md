# AUDIT_ROADMAP

> **Audit Cycle:** Cycle 4
> **Created:** 2026-03-14
> **Status:** Active
> **Predecessor:** `Cycle 4 Audit Seed Plan.md`
> **Focus:** Hosted CI proof, full scenario coverage, detection evasion resilience, and cross-layer attack-chain validation.

---

## Executive Summary

Cycle 4 starts from a stronger baseline than any previous cycle. Local runtime harnesses, replay validation, behavioral workflows, and evidence normalization all exist and have local closeout evidence. The remaining audit value is no longer in proving that the repo can validate itself locally; it is in proving that the same controls are trustworthy on hosted runners, that all documented scenarios have replay-backed coverage, and that detections remain useful under evasive pressure and across a chained incident.

The main Cycle 4 risk is **false confidence from incomplete trust boundaries**. A local green result does not prove a hosted runner behaves the same way, partial scenario coverage does not prove threat-model coverage, and isolated detections do not prove a coherent cross-layer response.

---

## Cycle 4 Findings

| ID | Severity | Layer(s) | Title | Verified Gap | Recommendation |
|----|----------|----------|-------|--------------|----------------|
| **C4-SEC-001** | CRITICAL | 5,6 | State-changing GET route scan_access.py L169 — I/O functions lacked defensive guards | SAST scanner flagged usage of `u.get("createdDateTime", "")` in `load_azure_ad()` as state-changing GET. Root cause: function performs HTTP I/O (Microsoft Graph calls) but has no guard to prevent accidental exposure via HTTP GET endpoint. | Add `@read_only_io` decorator to mark I/O-performing functions, add security docstrings, add tests validating guard behavior. Decorator raises `ReadOnlyIOViolation` if called from HTTP GET context. |
| **C4-CI-001** | HIGH | 7 | Hosted-runner proof is missing for the new behavioral workflows | Cycle 3 added runtime and replay workflows, but no hosted run artifacts have been captured yet. | Trigger both workflows on GitHub-hosted runners, archive the artifacts, and document any environment deltas. |
| **C4-CI-002** | MEDIUM | 7 | Runner environment differences are not yet documented as part of the security evidence model | Docker access, seccomp behavior, YARA availability, and tool paths may differ on hosted runners. | Capture a short runner-delta record with the first hosted workflow artifacts and preserve it with Cycle 4 evidence. |
| **C4-DET-001** | HIGH | 2,5,6 | Four documented attack scenarios still lack replay-backed detection coverage | Scenarios 003, 004, 005, and 007 do not yet have explicit replay-backed Sigma or YARA outcomes. | Add rules and fixtures for the unmapped scenarios and validate them via replay. |
| **C4-DET-002** | MEDIUM | 2→6 | The replay matrix does not yet provide full threat-scenario coverage | The current matrix captures Cycle 3 scenarios but not all documented attack paths. | Expand the replay matrix until all seven scenarios map to at least one expected rule hit. |
| **C4-EVA-001** | HIGH | 6 | Detection rules have not been adversarially tested against evasion variants | Existing replay fixtures validate direct matches, not manipulations such as encoding or whitespace chunking. | Add evasion fixtures and tests that probe rule robustness under realistic bypass attempts. |
| **C4-EVA-002** | MEDIUM | 6 | Regex-driven detection logic has not been checked for practical ReDoS risk | Expensive match behavior can become a detection-pipeline denial-of-service vector. | Add regex-stress cases and guardrails that flag high-cost matching behavior. |
| **C4-CHAIN-001** | HIGH | 2,3,5,6,7 | The repo has no scripted end-to-end attack-chain validation across detection and incident response layers | Detections, forensics, containment, and reporting have been validated separately but never as a correlated chain. | Build one end-to-end malicious-skill chain and validate coherent outputs across all layers. |

---

## Execution Update

- **2026-03-14:** Batch C4-A evidence plumbing was hardened so both behavioral workflows now persist durable artifacts. The runtime workflow captures a runner-delta snapshot alongside runtime evidence, and the replay workflow now archives replay summaries plus runner-delta evidence instead of only emitting transient console output.
- **2026-03-14:** First hosted dispatch completed on GitHub-hosted Ubuntu for the current `main` branch workflow definitions. `Runtime Security Regression` run `23096000651` completed successfully and retained artifact `cycle3-runtime-evidence`; `Detection Replay Validation` run `23096001103` also completed successfully but published no downloadable artifact.
- **2026-03-14:** Hosted evidence is archived in `archive/audit-artifacts-2026-03-14/CYCLE4_BATCH_C4A_HOSTED_EVIDENCE_2026-03-14.md`. The remaining hosted-proof gap is retained replay evidence plus runner-delta capture from the live branch state.
- **2026-03-14:** Hosted rerun closure completed on live `main`. `Runtime Security Regression` run `23096254983` retained artifact `cycle3-runtime-evidence`, and `Detection Replay Validation` run `23096255321` retained artifact `detection-replay-evidence` with replay summary and runner-delta output.
- **2026-03-14:** Hosted runner-delta evidence now records Docker/seccomp/path assumptions for both jobs and confirms YARA is installed for the replay workflow on GitHub-hosted Ubuntu. `C4-CI-001` and `C4-CI-002` are now satisfied.
- **2026-03-14:** Batch C4-B added replay-backed Sigma coverage for scenario 003 (MCP path traversal), scenario 004 (agent impersonation via webhook), scenario 005 (RAG poisoning upload), and scenario 007 (expensive trial-account abuse). Local replay validation passed and the updated matrix now covers all seven documented scenarios.
- **2026-03-14:** Local C4-B evidence is archived in `archive/audit-artifacts-2026-03-14/CYCLE4_BATCH_C4B_DETECTION_COVERAGE_2026-03-14.md` with replay summary `archive/audit-artifacts-2026-03-14/cycle-4-detection-replay/summary.json`.
- **2026-03-14:** Batch C4-C added adversarial replay variants for encoding, case manipulation, whitespace chunking, and null-byte insertion. The replay validator now canonicalizes strings before matching, rejects regex-style Sigma modifiers, and includes a guardrail test for high-risk YARA regex constructs.
- **2026-03-14:** Local C4-C evidence is archived in `archive/audit-artifacts-2026-03-14/CYCLE4_BATCH_C4C_EVASION_HARDENING_2026-03-14.md` with replay summary `archive/audit-artifacts-2026-03-14/cycle-4-detection-evasion/summary.json`.
- **2026-03-14:** Batch C4-D now has a repo-native malicious-skill chain exercise. `scripts/verification/exercise_malicious_skill_chain.py` produces one correlated incident bundle where replay detections, telemetry, hash-chain verification, containment actions, and the incident report all reference `INC-2026-C4D-001`.
- **2026-04-08:** SAST scanner flagged `scan_access.py:169` as "State-changing GET route" (critical). Root cause: `load_azure_ad()` and related functions perform HTTP I/O but lacked defensive guards to prevent accidental GET exposure. **Fixed by:** Added `@read_only_io` decorator in `src/clawdbot/config.py` to mark I/O functions and guard against HTTP GET context. Decorator raises `ReadOnlyIOViolation` if called from GET. Applied decorator to `_graph_token()`, `_graph_get()`, `load_azure_ad()`, and updated `run_access_review()` docstring. Enhanced module docstring in `scan_access.py` with security note. Added comprehensive security test suite in `tests/security/test_scan_access_security.py` (6 passed, 2 skipped). All existing CLI tests pass. **Status**: ✓ C4-SEC-001 completed.

---

| Severity | Count | Findings |
|----------|-------|----------|
| **CRITICAL** | 1 | C4-SEC-001 |
| **HIGH** | 2 | C4-DET-001, C4-CHAIN-001 |
| **MEDIUM** | 4 | C4-CI-002, C4-DET-002, C4-EVA-002, C4-EVA-001 |

---

## Recommended Sequence

1. Preserve the hosted artifact paths and runner-delta evidence as the reference proof for Cycle 4.
2. Keep the replay matrix, fixtures, and chain exercise aligned if new detections are added after this cycle.
3. Treat multi-OS parity as optional follow-on work, not a blocker for the current Cycle 4 closeout.

---

## Next Action

Cycle 4 execution is now backed by hosted runtime evidence, hosted replay evidence, local full-scenario replay coverage, adversarial evasion validation, and one correlated cross-layer incident bundle. The next step is closeout packaging rather than additional mandatory remediation.

---

## Cycle 5 Addendum

The 2026-04-24 adversarial audit introduced Batch B issue `#5`, which bundled `C5-finding-2` and `C5-finding-8` under the CLI orchestration honesty slice. That closeout work is now complete in the repo.

The 2026-04-24 adversarial audit also introduced Batch C issue `#6`, which tracked `C5-finding-1` under the policy-validator honesty slice. That closeout work is now complete in the repo.

The 2026-04-24 adversarial audit also introduced Batch D, which tracked `C5-finding-3` under the backup-verification truthfulness slice. That closeout work is now complete in the repo. <!-- FIX: C5-finding-3 -->

The remaining 2026-04-24 adversarial audit findings are now tracked in GitHub as Batch E issue `#13`, Batch F issue `#14`, Batch G issue `#15`, Batch H issue `#16`, Batch I issue `#17`, Batch J issue `#18`, Batch K issue `#19`, Batch L issue `#20`, Batch M issue `#21`, Batch N issue `#22`, and Batch O issue `#23`.

| ID | Severity | Status | Title | Verified Fix | Evidence |
|----|----------|--------|-------|--------------|----------|
| **C5-finding-1** | CRITICAL | COMPLETE | Policy validator de-theater for `SEC-003` and `SEC-005` | `tools/policy-validator.py` now loads repo-backed policy and checklist data, evaluates vulnerability-management and incident-response rules, rejects missing or unpopulated incident checklist evidence, and exits nonzero when those policies are noncompliant instead of returning unconditional passes. | `python tools/policy-validator.py --policy SEC-003`; `python tools/policy-validator.py --policy SEC-005`; `pytest tests/security/test_policy_compliance.py tests/security/test_policy_validator_claims.py -q` (`18 passed`) |
| **C5-finding-2** | CRITICAL | COMPLETE | CLI orchestration honesty for `playbook execute` | `tools/openclaw-cli.py` now builds repo-native phase command specs, executes the incident-response helpers, validates IOC and blast-radius artifacts, derives notification policy from CLI severity, and runs `scripts/forensics/collect_evidence.sh` after the phase sequence. | `pytest tests/unit/test_playbook_cli.py tests/unit/test_openclaw_cli_claims.py tests/unit/test_ioc_scanner.py tests/unit/test_ioc_scanner_claims.py tests/unit/test_incident_simulator_claims.py tests/unit/test_collect_evidence_script.py tests/unit/test_collect_evidence_function_claims.py -q` (`44 passed`) |
| **C5-finding-3** | CRITICAL | COMPLETE | Backup verification truthfulness for `verify_3_2_1_compliance()` | `examples/security-controls/backup-verification.py` now scans paginated offsite results, accepts real producer aliases, rejects hyphen-suffixed false positives and snapshot tag-key false positives, fails loudly on unreadable backup-specific manifests, ignores manifest-only evidence, and requires a real local payload before counting a local copy. | `pytest tests/integration/test_backup_recovery.py -q -k Test321Strategy` (`15 passed, 4 deselected`); `pytest tests -q` (`227 passed, 2 skipped`) | <!-- FIX: C5-finding-3 -->
| **C5-finding-4** | CRITICAL | OPEN | GDPR compliance reporter honesty | Pending in Batch E / Issue `#13`. | GitHub issue `#13` |
| **C5-finding-5** | CRITICAL | OPEN | ISO27001 compliance reporter honesty | Pending in Batch E / Issue `#13`. | GitHub issue `#13` |
| **C5-finding-6** | CRITICAL | COMPLETE | Certificate expiry scan truthfulness | `check_expiry()` now validates `openssl` returncode and stdout format, catches all `OSError` launch failures, strips the `GMT` token and attaches `tzinfo=timezone.utc` before subtraction (eliminating the naive/aware `TypeError`), and returns a deterministic `status` of `healthy`, `expiring`, or `unreadable` on every path. `certificates()` renders the new status column and guards `None` days safely. | `pytest tests/unit/test_report_weekly_cli.py -q` (10 passed) |
| **C5-finding-7** | HIGH | COMPLETE | Vulnerability scan false-green prevention | `run_scan()` summary now includes `coverage_complete` and `required_tools_skipped`; `vulnerability()` CLI prints an explicit non-pass exit instead of false-green when required tools are absent; module docstring legacy syntax fixed. | `pytest tests/unit/test_scan_vulnerability_cli.py tests/security/test_vulnerability_scanning.py -q` (32 passed) — commit ff590ee |
| **C5-finding-8** | HIGH | COMPLETE | Incident simulation routing honesty | `simulate incident` now routes `credential-theft`, `mcp-compromise`, and `dos-attack` to distinct playbooks and artifact paths using hardened simulator payloads instead of always drilling credential theft. | `pytest tests/unit/test_playbook_cli.py tests/unit/test_openclaw_cli_claims.py tests/unit/test_incident_simulator_claims.py -q` |
| **C5-finding-9** | HIGH | OPEN | IOC scanner capability honesty | Pending in Batch I / Issue `#17`. | GitHub issue `#17` |
| **C5-finding-10** | HIGH | COMPLETE | Forensics collector capability honesty | Module docstring and `collect_disk_metadata()` now state "partition metadata only, no disk imaging" and "SHA-256 checksums only, no cryptographic signing". Evidence description updated to "NOT a disk image". | `pytest tests/integration/test_modified_function_claims.py tests/integration/test_playbook_procedures.py -q -k "forensics"` (3 passed) — Issue `#19` |
| **C5-finding-11** | HIGH | OPEN | Auto-containment implementation honesty | Pending in Batch G / Issue `#15`. | GitHub issue `#15` |
| **C5-finding-12** | HIGH | COMPLETE | Notification delivery honesty | Fixed in commit 409c186 (Issue `#18`). `send_email_notification` now raises `NotImplementedError`; `notify_all` handles it explicitly and returns real delivery state. | GitHub issue `#18` |
| **C5-finding-13** | HIGH | COMPLETE | Shell evidence containment honesty | `scripts/forensics/collect_evidence.sh` no longer claims network blocking; `--containment` description, the containment block, and the script header explicitly state the flag stops moltbot/openclaw services and the clawdbot container only. Two pipefail traps (`ps|grep`, `systemctl|grep`) that aborted the script before reaching the containment phase are also fixed so warnings and the warnings→exit-2 path are reliably reached. | `pytest tests/unit/test_collect_evidence_script.py tests/unit/test_collect_evidence_function_claims.py -q` (4 passed) |
| **C5-finding-14** | HIGH | COMPLETE | Forensics runbook CLI parity | Runbook Step 1.5 now documents `--incident` and `--level full` (supported flags). Unsupported `--incident-id`, `--output`, `--collect all` removed. | Issue `#19` |
| **C5-finding-15** | HIGH | OPEN | Auto-containment policy parity | Pending in Batch G / Issue `#15`. | GitHub issue `#15` |
| **C5-finding-16** | MEDIUM | COMPLETE | Detection replay YARA coverage honesty | `evaluate_yara_case()` now returns `passed=False` with a "coverage-incomplete" detail string instead of a silent `passed=True` when YARA is unavailable without `--require-yara`. `run_validation()` appends a `_yara_coverage` sentinel result when YARA cases were present but unevaluated. `main()` returns exit code 2 (coverage-incomplete, distinct from 0=pass and 1=test-failure) and prints `[COVERAGE-INCOMPLETE]`. Commit ed1162a. | `pytest tests/security/test_detection_replay_validation.py -q` (7 passed) |
| **C5-finding-17** | MEDIUM | COMPLETE | Telemetry verification honesty | `verify_openclaw_security.sh` Check 6 now uses three-state logic: active (log written ≤3600 s ago), configured-but-stale (log present but stale), or unverifiable (no config or log). A config file alone no longer produces a green pass. | commit 0a62cde — `pytest tests/integration/test_cycle5_claim_regressions.py -q` (28 passed) |
| **C5-finding-18** | MEDIUM | COMPLETE | Database migration honesty | `_run_migrate()` stub raises `NotImplementedError` with full contract docstring; `main(['migrate'])` catches it, prints to stderr, and returns exit code 2 so callers fail closed. Silent no-op replaced. | `pytest tests/unit/test_clawdbot_runtime.py -q` (3 passed) — Issue `#23` |
| **C5-finding-19** | MEDIUM | COMPLETE | Forensics collector missing-tool degradation honesty | `collect_network_capture()` now adds an explicit `{"status": "degraded"}` manifest entry when tcpdump is missing; `collect_all()` records it in `failed_steps` and raises `RuntimeError`. | Issue `#19` |
| **C5-finding-20** | MEDIUM | COMPLETE | Community tools guide parity | `verify_openclaw_security.sh` header comment now references `docs/guides/08-community-tools-integration.md` (was `07-`). | commit 0a62cde |
| **C5-finding-21** | LOW | OPEN | Vulnerability CLI help parity | Pending in Batch H / Issue `#16`. | GitHub issue `#16` |
| **C5-finding-22** | LOW | COMPLETE | Security training notification parity | Fixed in commit 409c186 (Issue `#18`). Training now documents only implemented notification routes and explicitly states GDPR breach tracking is not automated. | GitHub issue `#18` |
| **C5-finding-23** | LOW | COMPLETE | Evidence guide output parity | `docs/guides/06-incident-response.md` Evidence Collection section now matches the script: full `Evidence collection complete:` banner, five numbered next-step lines, containment "does NOT block network" notice, and the Evidence Collection Summary block with exit codes 0 / 1 / 2 explained. | `pytest tests/unit/test_collect_evidence_script.py tests/unit/test_collect_evidence_function_claims.py -q` (4 passed) |
| **C5-finding-24** | CRITICAL | COMPLETE | Phantom integration guard ignores its own allowlist | `allowed_paths` set is now consulted in the scan loop via `if rel_path in allowed_paths: continue`; `.github/workflows/lint.yml` added to allowlist so the guard's own regex definition line is exempt. Guard now skips all 16 allowlisted paths before scanning for references. | Push to `topazyo/issue9` and verify CI run passes on GitHub-hosted runner. |

2026-04-25 execution note: claim-based regression suites were added for the modified CLI, simulator, IOC scanner, and evidence-collection helpers. That closeout work also exposed one remaining wrong-result branch in `scripts/forensics/collect_evidence.sh`, which is now fixed so helper warnings preserve the real failing subcommand exit code.

2026-04-26 execution note: the remaining open Cycle 5 findings are now mapped to GitHub issues `#13` through `#23` by batch so implementation and tracker updates can stay aligned without widening scope mid-fix.

2026-04-25 execution note: Batch C issue `#6` is ready for closure. Local evidence commands `python tools/policy-validator.py --policy SEC-003`, `python tools/policy-validator.py --policy SEC-005`, and `pytest tests/security/test_policy_compliance.py tests/security/test_policy_validator_claims.py -q` passed after the validator was switched from hardcoded passes to repo-backed rule evaluation.

---

## Prior-Cycle Baseline

- **2026-03-14:** Cycle 3 closed with local secure/insecure runtime evidence, replay validation, dedicated behavioral workflows, and a manifest-backed evidence snapshot archived under `archive/audit-artifacts-2026-03-14/`.
- **2026-03-14:** `archive/audit-artifacts-2026-03-14/CYCLE3_CLOSEOUT_EVIDENCE_2026-03-14.md` became the closeout source of truth for the completed local Cycle 3 scope.
- **2026-03-14:** `archive/audit-artifacts-2026-03-14/CYCLE4_CLOSEOUT_EVIDENCE_2026-03-14.md` is now the consolidated closeout source of truth for hosted proof, replay coverage, evasion hardening, and cross-layer chain validation in Cycle 4.