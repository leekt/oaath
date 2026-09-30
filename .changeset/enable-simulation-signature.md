---
"@oaath/sdk": patch
---

`@oaath/sdk/kernel` exports `bindKernelPermissionEnable({ runtime, account,
approval })`. It prepares a session's enable-mode first execution without
signing, and returns a `simulationSignature` for `eth_estimateUserOperationGas`:
the exact enable envelope around the session key's placeholder. After
estimating, `signOperation` asks the session key once. The ECDSA placeholder
signature is now a recoverable low-s signature, so an ECDSA signer module
reports a signature failure during estimation instead of reverting.
