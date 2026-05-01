---
name: high-fix
description: HIGH finding fix — code that runs but does not do what it claims
---
You are fixing a HIGH finding — a functional gap. The code runs but the claim 
it makes is false. Your fix must make the claim TRUE. After implementing:
trace the function end-to-end and narrate how the claim is now satisfied.
If the fix requires an unwired integration, implement an explicit stub 
with NotImplementedError, not a silent pass.