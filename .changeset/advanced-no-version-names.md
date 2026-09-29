---
"@oaath/sdk": minor
"@oaath/testing": patch
"oaath": patch
---

Breaking: no `@oaath/sdk` entry exports a name that includes a Kernel version
(`V33`/`V4`). This now covers `@oaath/sdk/advanced` too, and
`check:public-surface` enforces it for every published entry.

- Deployment addresses and code hashes come from `kernelDeployment(...)`
  fields. The `KERNEL_V4_*` constants are removed.
- `encodeKernelNonceKey({ deployment, ... })` replaces `encodeKernelV4NonceKey`
  and `encodeKernelV33NonceKey`.
- `kernelOperationSigningHash({ deployment, operation })` replaces
  `kernelV33OperationSigningHash`.
- The other version-named encoders keep their generic names:
  `encodeKernelNonceRead`, `encodeKernelFactoryImplementationRead`,
  `encodeKernelInstallNonceRead`, `encodeKernelInstallNonceInvalidationCall`
  and `kernelReplayableInstallDigest`.
- `OAATH_KERNEL_VALIDITY_POLICY` and its code hash replace the
  `OAATH_KERNEL_V4_*` names.
- `OAATH_KERNEL_PERMISSION_ENABLE_APPROVAL_VERSION` on `@oaath/sdk/kernel`
  replaces `OAATH_KERNEL_V33_APPROVAL_VERSION`.
- The Kernel v3.3 permission-state helpers and
  `kernelV33PermissionEnableTypedData` become internal.
  `prepareKernelPermissionRevocation`, `verifyKernelPermissionRevocation` and
  `kernelPermissionEnableTypedData` replace them.
- The CLI and the testing fixtures use the generic forms.
