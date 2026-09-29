---
"@oaath/sdk": patch
---

Add explicit Grant signer auto selection. Available owner authority executes one atomic UserOperation without enabling a session; public-only owner profiles retain session execution. Reviews distinguish root authority from onchain Grant policy, and both paths retain the same durable execution lane and recovery behavior.
