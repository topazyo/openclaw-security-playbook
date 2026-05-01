---
name: issue-template
description: Standard GitHub Issue body format for audit fix issues
---
Every issue must follow this structure:

## Finding
[Finding # and exact audit description]

## Files affected
- `path/to/file` — function `name()`

## Acceptance criteria
- [ ] [Specific, verifiable, claim-based criterion]
- [ ] [Second criterion]

## Verification step
[Exact command or test to run that proves the fix works]

## Do NOT change
[Files and signatures that must remain untouched]

## Severity
[CRITICAL / HIGH / MEDIUM]