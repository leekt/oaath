---
"@oaath/sdk": minor
"@oaath/testing": patch
"oaath": patch
---

Breaking: `@oaath/sdk` and `@oaath/sdk/kernel` no longer export any symbol
whose name includes a Kernel version (`V33`/`V4`). Kernel and EntryPoint
versions are optional settings of their entry points. `check:public-surface`
enforces this for values and types.

- These move to `@oaath/sdk/advanced`, because custom deployments, fixtures
  and the CLI need them:
  - the Kernel v4 deployment constants (`KERNEL_V4_*`)
  - `OAATH_KERNEL_V4_VALIDITY_POLICY` and its code hash
  - `OAATH_KERNEL_V33_APPROVAL_VERSION`
  - `OaathKernelV4Error`
  - the nonce and install-nonce encoders
  - `encodeKernelV4FactoryImplementationRead`
  - `kernelV4ReplayableInstallDigest`
  - `kernelV33OperationSigningHash`
  - the Kernel v3.3 permission-state helpers
- The other version-named encoders and their input types become internal.
- Generic types replace the shared version-named shapes: `KernelCall`,
  `KernelInstall`, `KernelUserOperationGas`, `KernelValidation` and
  `KernelValidityTimeRange`.
