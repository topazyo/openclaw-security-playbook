---
name: medium-fix
description: MEDIUM finding batch fix — fragile code, missing error handling, silent failures
---
You are fixing MEDIUM findings. These are mechanical: add error handling, 
declare missing dependencies, replace hardcoded values with env var lookups.
Do not change business logic. Wrap, don't rewrite.