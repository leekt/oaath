---
"@oaath/sdk": minor
"@oaath/testing": patch
---

Add version-agnostic permission approval entry points to `@oaath/sdk/kernel`.
Each one uses the session runtime's deployment:

- `approveKernelPermission({ owner, runtime, account, nonce })`
- `kernelPermissionNonce({ runtime, account, reads, requestHash })`
- `kernelPermissionEnableTypedData({ runtime, account, nonce })`
- `materializeKernelPermission`
- `parseKernelPermissionApproval`
- `kernelPermissionCapabilityHash`

The matching types are `KernelPermissionApproval`, `KernelExpectedPermission`,
`KernelApprovalMismatchField` and `KernelApprovalMismatchReason`.

Local mode's approval review and `signTypedData` request are typed as
`KernelPermissionEnableTypedData`. The review comes from the account's selected
deployment, not a Kernel `0.3.3` literal.

Breaking: `approveKernelPermissionAllChain`, `approveKernelV33Permission`,
`parseKernelAllChainApproval`, `parseKernelV33PermissionApproval`,
`kernelAllChainCapabilityHash`, `kernelV33CapabilityHash`,
`kernelPermissionInstallNonce`, `kernelV33PermissionInstallNonce`,
`kernelV33PermissionEnableTypedData` and `materializeKernelV33Permission` are no
longer exported from `@oaath/sdk/kernel`. `kernelV33PermissionEnableTypedData`
moves to `@oaath/sdk/advanced`.
