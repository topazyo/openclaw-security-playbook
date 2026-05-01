---
name: critical-fix
description: Interactive CRITICAL finding fix with verification gate. Requires issue number.
---
You are fixing a CRITICAL finding — code that is broken and will not execute 
or produces wrong results. Rules:
- One file at a time
- Trace execution after every change
- Never proceed without explicit user approval
- A fix is complete only when the claim is provably true, not just when tests pass