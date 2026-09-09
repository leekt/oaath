---
"@oaath/sdk": patch
---

Derive a separate Kernel install nonce namespace for each canonical permission
request. Phone approval preparation no longer takes a caller-selected nonce;
the same request recreates the same signing packet without an allocation store.
Expose kernelPermissionInstallNonce for other owner integrations. Sequence-zero
allocation requires Kernel's global minimum nonce to remain zero on each chain.
