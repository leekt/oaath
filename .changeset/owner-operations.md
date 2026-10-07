---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

Add owner operations for factory-derived Kernel 0.4.0 accounts. `@oaath/protocol` captures `oaath.owner-operation-request/v1` and `oaath.signed-owner-operation/v1`: one exact EntryPoint 0.9 UserOperation whose hash, signed by the account root, binds chain, EntryPoint, account, nonce, calls, gas, factory and paymaster. `@oaath/sdk/kernel` adds `prepareOwnerOperation`, which builds the request offline and has an ECDSA, P-256 or WebAuthn root sign it, and `verifyOwnerOperation`, which checks the account derivation, factory deployment and root signature and returns the ERC-4337 JSON-RPC operation to submit.
