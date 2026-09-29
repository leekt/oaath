---
"@oaath/sdk": minor
---

`@oaath/sdk/advanced` gains version-agnostic forms of its Kernel encoders:

- `encodeKernelNonceKey({ deployment, mode, validation, nonceKey })` encodes
  the EntryPoint nonce key for the deployment's Kernel version.
- `kernelOperationSigningHash({ deployment, operation })` returns the digest
  an external signer signs for that Kernel version.
- `encodeKernelNonceRead`, `encodeKernelFactoryImplementationRead`,
  `encodeKernelInstallNonceRead`, `encodeKernelInstallNonceInvalidationCall`,
  `kernelReplayableInstallDigest`, `OAATH_KERNEL_VALIDITY_POLICY` and
  `OAATH_KERNEL_VALIDITY_POLICY_RUNTIME_CODE_HASH`.

`kernelDeployment(...)` now includes `entryPoint.runtimeCodeHash` and
`create2Deployer`. The Kernel `0.4.0` profile also includes
`factoryRuntimeCodeHash`. `@oaath/sdk/kernel` exports
`OAATH_KERNEL_PERMISSION_ENABLE_APPROVAL_VERSION`, the version of the Kernel
`0.3.3` permission-enable approval.
