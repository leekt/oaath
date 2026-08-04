---
---

Materialize @oaath/sdk Kernel permissions on every supported chain from one owner
approval. `approveKernelPermissionAllChain` takes a single signature over Kernel
v4's replayable enable digest, whose EIP-712 domain omits the chain id and binds
only the account, the install nonce and the exact install packages, and
`materializeKernelPermission` spends it on each chain — including one introduced
after the approval — as the session's first enable-mode operation. No release.
