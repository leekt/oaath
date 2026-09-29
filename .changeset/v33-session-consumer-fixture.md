---
"@oaath/testing": minor
---

The public local-chain fixture can now use an existing Kernel v3.3 account on
each chain, approve one all-chain permission, and recover retained operations
without credentials. Its explicit recovery descriptor is v2 and carries the
existing account address. Older fixture descriptors are rejected and recreated.
Both owner and session fixtures share the same real account deployment.
