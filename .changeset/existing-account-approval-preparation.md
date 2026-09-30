---
"@oaath/sdk": patch
---

`@oaath/sdk/kernel` exports `prepareExistingAccountPermissionApproval({
account, owner, operator, chains, requestHash, kernelVersion? })`. For an
existing Kernel account it binds the account on every given chain, proves the
owner key is the onchain root owner on each one, and returns the one approval's
`nonce`, `typedData` and `digest`. It needs no `PermissionRequest`. Chains whose
effective enable nonces differ fail with the new
`kernel_runtime_nonce_mismatch` code.
