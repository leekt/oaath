---
"@oaath/sdk": patch
---

Grant approval never reads a chain. `prepareExistingAccountPermissionApprovalOffline` no longer requires `enableNonce`: omitted, a Kernel 0.3.3 approval signs `KERNEL_FRESH_ENABLE_NONCE` (`"1"`, the effective enable nonce of an account that is not deployed, since Kernel's `initialize` sets `currentNonce` to 1), and a malformed nonce refuses as `kernel_runtime_input_invalid`. The OAAth portal now builds every approval offline from the app's `enableNonce` or that fresh nonce, so an undeployed (counterfactual) account is approved with no RPC; a nonce that has moved installs nothing at execution rather than blocking approval. `rpcUrls` is no longer read for approval.
