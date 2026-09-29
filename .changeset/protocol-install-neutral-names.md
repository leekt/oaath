---
"@oaath/protocol": minor
"@oaath/sdk": patch
"@oaath/server": patch
---

Breaking: no `@oaath/protocol` export names a Kernel version, and
`check:public-surface` now bans `V33`/`V4` export names on every published
`@oaath/protocol`, `@oaath/server` and `@oaath/testing` entry as well as
`@oaath/sdk`. Wire and persisted version strings are unchanged.

- `KERNEL_INSTALL_COMPONENTS`, `parseKernelInstallPackages`,
  `createKernelReplayableInstallTypedData` and
  `parseKernelReplayableInstallOwnerSigningRequest` replace their `KernelV4`
  forms.
- The types `KernelModuleType`, `KernelReplayableInstallPackage`,
  `KernelReplayableInstallTypedData`, `KernelReplayableInstallTypedDataInput`
  and `KernelReplayableInstallOwnerSigningRequest` replace their `KernelV4`
  forms.
- `KernelDerivedAccountProfile` replaces `KernelV4AccountProfile`, the derived
  counterpart of `KernelExistingAccountProfile`.
