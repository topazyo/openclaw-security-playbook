# OpenClaw MITRE ATLAS Threat Mapping

This document maps the three primary attack vectors covered in the blog series to their
official MITRE ATLAS taxonomy from [trust.openclaw.ai/trust/threatmodel](https://trust.openclaw.ai/trust/threatmodel).

Use these IDs when filing tickets, building detection rules, and aligning with your
security team's existing MITRE-based workflows.

## Primary Attack Vectors (Parts 1 and 2)

| Attack Vector | OWASP LLM | NIST CSF | MITRE ATLAS |
|---|---|---|---|
| Backup credential file persistence | LLM06 | PR.DS-1 | T-EXFIL-003 |
| Localhost authentication bypass | LLM04 | PR.AC-5 | T-ACCESS-002 |
| Prompt injection (direct) | LLM01 | PR.PT | T-EXEC-001 |
| Prompt injection (indirect/email) | LLM01 | PR.PT | T-EXEC-002 |
| Supply chain / malicious skill | LLM04 | ID.SC | T-ACCESS-004, T-EXEC-005 |
| Behavioral monitoring (detection) | — | DE.AE, DE.CM | T-DETECT-001 |

## Critical Kill Chains (Part 3)

### Kill Chain 1: Prompt Injection to Remote Code Execution
```
T-ACCESS-006 (Gain channel access)
  -> T-EXEC-001 (Inject prompt via external channel)
  -> T-EVADE-003 (Manipulate confirmation dialog)
  -> T-EXEC-004 (Bypass exec approval)
  -> T-IMPACT-001 (Execute commands on host)
```
**Detection:** Hunt 1 (off-hours exec) + Kill Chain 1 query (inbound msg to high-risk tool)

### Kill Chain 2: Indirect Injection Data Theft
```
T-EXEC-002 (Poison fetched content)
  -> T-DISC-004 (Agent enumerates environment)
  -> T-EXFIL-001 (Exfiltrate via web_fetch or HTTP tool)
```
**Detection:** Hunt 2 (web_fetch -> file_read sequence)

### Kill Chain 3: Malicious Skill Full Kill Chain
```
T-RECON-003 (Research ClawHub)
  -> T-EVADE-001 (Publish evasive skill)
  -> T-ACCESS-004 (User installs skill)
  -> T-EXEC-005 (Skill executes payload)
  -> T-PERSIST-001 (Establish persistence via SOUL.md)
  -> T-EXFIL-003 (Harvest credentials)
```
**Detection:** Sigma rule openclaw-skill-child-process.yml + Hunt 5 (SOUL.md writes)

### Kill Chain 4: Supply Chain Staged Payload
```
T-ACCESS-005 (Compromise skill publisher)
  -> T-EVADE-004 (Push update with benign first run)
  -> T-EXEC-005 (Retrieve payload on second execution)
  -> T-PERSIST-002 (Establish secondary persistence)
  -> T-EXFIL-004 (Exfiltrate via secondary channel)
```
**Detection:** Kill Chain 4 query (unexpected web_fetch from skill context)

### Kill Chain 5: Token Theft Persistent Access
```
T-ACCESS-003 (Steal authentication token)
  -> T-PERSIST-004 (Reuse token for persistent access)
  -> T-DISC-002 (Extract session data and transcripts)
  -> T-EXFIL-002 (Exfiltrate via messaging integrations)
```
**Detection:** Kill Chain 5 query (token reuse across sessions)

## Three Additional Threat Classes

| Threat | ATLAS ID | Description | Partial Mitigation |
|---|---|---|---|
| Transcript exfiltration | T-EXFIL-004 | Conversation history leaked via tool or file access | Exclude transcript paths from container mounts |
| Memory poisoning | T-PERSIST-005 | Injected instructions persist in agent memory across sessions | SOUL.md write monitoring (Hunt 5) |
| Financial fraud via agent | T-IMPACT-005 | Prompt injection triggers fraudulent transactions via payment tools | Require human confirmation for all financial operations |

## Framework Cross-Reference

| ATLAS Tactic | MITRE ATT&CK Analog | OWASP LLM | Key Controls |
|---|---|---|---|
| AML.TA0002 (ML Attack Staging) | Reconnaissance (TA0043) | LLM04 | Skill vetting, supply chain integrity |
| AML.TA0003 (ML Attack Execution) | Execution (TA0002) | LLM01, LLM09 | Tool gating, sandboxing, confirmation dialogs |
| AML.TA0005 (ML Defense Evasion) | Defense Evasion (TA0005) | LLM01 | Behavioral monitoring, hash chain integrity |
| AML.TA0009 (ML Exfiltration) | Exfiltration (TA0010) | LLM06 | OS Keychain, path restrictions, email_send confirmation |
| AML.TA0011 (ML Impact) | Impact (TA0040) | LLM09 | Least-privilege tool access, rate limits |
