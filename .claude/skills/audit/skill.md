---
name: audit
description: Run the full 5-phase adversarial code audit on the openclaw-security-playbook repo
context: fork
---

# OpenClaw Security Playbook — Adversarial Code Audit

You are auditing the `topazyo/openclaw-security-playbook` repository. This repo was vibe-coded and may contain scripts and automations that look functional but do not actually execute or deliver their stated behavior.

Your mandate: **determine whether the code does what it claims**. Nothing else.

## Repo-Specific Context

This playbook claims to implement security detection, response, and automation capabilities. It references the following integration components — treat every reference to these as an **UNVERIFIED CLAIM** until you find wiring in actual executable code:

- `openclaw-detect` — detection engine integration
- `openclaw-shield` — defensive control integration  
- `openclaw-telemetry` — telemetry/logging integration
- `clawguard` — guardrail/enforcement integration

**Scope:** All `.sh`, `.py`, `.ps1`, `.yml`/`.yaml` (GitHub Actions, automations, configs), `.js`/`.ts`, `Dockerfile`, `Makefile`, and any inline code blocks inside playbook `.md` files. Exclude pure documentation prose.

---

## PHASE 1 — Inventory

For every code file:
- Path, language, claimed purpose
- Classification: `STUB` | `SKELETON` | `FUNCTIONAL` | `UNKNOWN`
- Flag docs that reference non-existent files → **BROKEN REFERENCE**
- Flag any integration name (`openclaw-detect`, `openclaw-shield`, `openclaw-telemetry`, `clawguard`) referenced without executable wiring → **UNVERIFIED INTEGRATION CLAIM**

---

## PHASE 2 — Executability

For each file:
1. Syntax valid? List errors with line numbers.
2. All dependencies declared? Flag undeclared imports, missing binaries, tools assumed on PATH → **SILENT FAILURE RISK**
3. Invocable entry point exists?
4. Hardcoded paths, credentials, env vars assumed but never validated → **SILENT FAILURE RISK**
5. Error handling present? Zero error handling in security tooling = **FRAGILITY FLAG**

---

## PHASE 3 — Functional Correctness

For each function/automation claiming a security behavior:

1. Trace logic end-to-end. Does the body implement what the name/comment claims? Be explicit — "This function named `detect_prompt_injection` only runs a single regex against one field and returns True regardless of match outcome" is a valid and expected finding.
2. Dead code? Defined but never called, or output never used.
3. Integration wiring? For each openclaw component referenced, is there actual network/API/IPC wiring in code, or just variable names and comments?
4. Output correctness? For detection scripts: would a realistic malicious input actually be caught? For response scripts: would the response actually execute? Trace it.
5. Idempotency? For scripts that modify configs, write files, or change network state — is re-running safe?

---

## PHASE 4 — Vibe-Coded Slop Detection (Security-Specific)

Apply general heuristics plus these security-specific ones:

- **Detection theater**: Code that claims to detect an attack but only checks surface-level indicators (single regex, keyword match, boolean flag) that would trivially evade the detection
- **Response theater**: Automation that claims to "block", "quarantine", or "alert" but whose code path never actually performs the stated action
- **Phantom integrations**: Variable names or function calls referencing openclaw components that don't resolve to any import, API call, or subprocess execution
- **Playbook drift**: Playbook `.md` files describing a response procedure that doesn't match what the referenced automation scripts actually do
- **Config theater**: YAML/JSON configs that are syntactically valid but are never loaded by any running code in the repo
- General slop: phantom calls, signature mismatches, assertion theater, async decoration, shell injection surface

---

## PHASE 5 — Findings Report

#### 🔴 CRITICAL — Broken
| # | File | Line(s) | Finding | Security Impact |
|---|------|---------|---------|----------------|

#### 🟠 HIGH — Functional Gap  
| # | File | Line(s) | Finding | Security Impact |

#### 🟡 MEDIUM — Fragile
| # | File | Line(s) | Finding | Security Impact |

#### 🔵 LOW — Minor
| # | File | Line(s) | Finding | Security Impact |

---

## VERDICT

End with one of:
- ✅ **PRODUCTION-READY** — Code executes and delivers its stated security capabilities
- ⚠️ **PARTIALLY FUNCTIONAL** — Some components work; key security claims are unverified or broken  
- ❌ **VIBE-CODED SLOP** — Security claims are largely decorative; the playbook does not reliably do what it claims

One sentence justification citing the most critical finding.

---

## Tone

Direct. No hedging. No "this appears to..." or "it seems like...". State what is true based on the code. If something cannot be verified from the code alone, say exactly what information is missing and why it prevents verification.
