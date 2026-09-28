---
"@oaath/protocol": minor
"@oaath/sdk": minor
"@oaath/server": patch
---

Add a distinct existing-account identity profile for Kernel 0.3.3, binding its
address and ECDSA owner without a factory index. Permission request hashes,
Grant identity comparisons, and browser bindings include the existing address.
Phone approval and enrollment remain scoped to their supported v4 profiles.
High-level v3.3 Grant execution is still pending its runtime integration.
