---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

`prepareKernelPermissionRevocation` accepts an optional caller-supplied EntryPoint 0.7
`paymaster` (`address`, `verificationGasLimit`, `postOpGasLimit`, `data`) for Kernel `0.3.3`
and `0.4.0`; it defaults to `null` (self-funded) and is part of the hashed operation identity.
The Kernel `0.3.3` record is now `oaath.kernel-permission-revocation/v2` with a top-level
`paymaster`; `v1` records are rejected and must be prepared again. The Kernel `0.4.0`
revocation signing request accepts a packed `paymasterAndData`, and restore reproduces the
exact sponsored operation.
