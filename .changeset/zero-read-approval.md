---
"@oaath/sdk": patch
---

Grant approval for an existing account can read no chain. `requestPermissionApproval` takes an optional `enableNonce` (a Kernel 0.3.3 account's effective enable nonce for that signer and policy, decimal uint32 > 0), sent as the `oaath_grant` detail's `enable_nonce`; the portal then prepares the approval offline. Kernel 0.4.0 existing accounts never need it. `prepareExistingAccountPermissionApprovalOffline` (`@oaath/sdk/kernel`) prepares the same signing request and decision as the read-backed preparation, from the request and that nonce alone.
