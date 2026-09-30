---
"@oaath/sdk": patch
---

`readKernelPermissionStatus` on `@oaath/sdk/kernel` reads one approval's
permission status from plain `KernelReads` (for example `createKernelReads`) at
a named block, `latest` or `finalized`: `installed`, `approval-replayable`,
`revoked` or `unreadable`. It classifies with the same owner as
`verifyKernelPermissionRevocation`. Kernel `0.4.0` approvals return
`unsupported`. The `kernel_v33_permission_state` read accepts an optional
`blockTag`, which `createKernelReads` forwards to every `eth_call`.
